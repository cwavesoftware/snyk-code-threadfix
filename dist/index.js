#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import * as events from 'events';
import orderBy from 'lodash.orderby';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const codeSeverityMap = {
    error: 'high',
    warning: 'medium',
    info: 'low',
    note: 'low',
};
const tfSeverityMap = {
    error: 'High',
    warning: 'Medium',
    info: 'Low',
    note: 'Low',
};
var sarif = function (snyk) {
    snyk = JSON.parse(snyk);
    let tf;
    tf = fs.readFileSync('sample.threadfix', 'utf8');
    tf = JSON.parse(tf);
    console.log(tf);
    const now = new Date().toISOString().replace(/\.\d\d\dZ/, 'Z');
    tf.created = now;
    tf.updated = now;
    tf.exported = now;
    tf.findings = [];
    let rules = {};
    snyk.runs[0].tool.driver.rules.forEach((rule) => {
        rules[rule.id] = rule;
    });
    snyk.runs[0].results.forEach((res) => {
        let df = [];
        res.codeFlows[0].threadFlows[0].locations.forEach((loc) => {
            df.push({
                file: loc.location.physicalLocation.artifactLocation.uri,
                lineNumber: loc.location.physicalLocation.region.startLine,
                columnNumber: loc.location.physicalLocation.region.startColumn,
                text: `${loc.location.physicalLocation.codeString[0].codepremarker}${loc.location.physicalLocation.codeString[0].block}${loc.location.physicalLocation.codeString[0].codemarker}${loc.location.physicalLocation.codeString[0].codepostmarker}`
            });
        });
        tf.findings.push({
            nativeId: res.fingerprints['0'],
            severity: codeSeverityMap[res.level],
            nativeSeverity: res.level,
            summary: rules[res.ruleId].shortDescription.text,
            description: res.message.text,
            scannerDetail: '',
            scannerRecommendation: rules[res.ruleId].help.markdown,
            staticDetails: {
                file: res.locations[0].physicalLocation.artifactLocation.uri,
                parameter: `line ${res.locations[0].physicalLocation.region.startLine}`,
                dataFlow: df
            }
        });
    });
    return tf;
};
async function processCodeLine(filePath, region) {
    try {
        const endLine = region.endLine;
        const startLine = region.startLine;
        const multiLine = region.startLine == endLine ? false : true;
        const codeString = [];
        let lineNumber = 1;
        let parseline = '';
        let columnEndOfLine;
        const codeMarker = { codelineno: 0, block: multiLine, codesource: "", codepremarker: "", codemarker: "", codepostmarker: "" };
        const sourceFs = fs.createReadStream(filePath);
        const rl = readline.createInterface({
            input: sourceFs
        });
        rl.on('line', (line) => {
            parseline = line.toString();
            if (lineNumber == startLine) {
                if (multiLine) {
                    columnEndOfLine = parseline.length;
                }
                else {
                    columnEndOfLine = region.endColumn;
                }
                codeMarker.codelineno = lineNumber;
                codeMarker.codepremarker = parseline.substring(0, region.startColumn - 1);
                codeMarker.codemarker = parseline.substring(region.startColumn - 1, columnEndOfLine);
            }
            if (lineNumber == endLine) {
                if (multiLine) {
                    codeMarker.codemarker = codeMarker.codemarker + "\n" + parseline.substring(0, region.endColumn);
                }
                codeMarker.codepostmarker = parseline.substring(region.endColumn, parseline.length);
                codeString.push(codeMarker);
                rl.close();
            }
            if (lineNumber > startLine && lineNumber < endLine) {
                codeMarker.codemarker = codeMarker.codemarker + "\n" + parseline;
            }
            lineNumber++;
        });
        await events.once(rl, 'close');
        sourceFs.close();
        return codeString;
    }
    catch (err) {
        console.error(err);
    }
}
;
async function readCodeSnippet(codeInfomation) {
    const decodedpath = decodeURI(codeInfomation.physicalLocation.artifactLocation.uri);
    const filePath = path.resolve(process.argv[3], decodedpath);
    const codeRegion = codeInfomation.physicalLocation.region;
    const result = await processCodeLine(filePath, codeRegion);
    return result;
}
async function processSourceCode(dataArray) {
    let test = [];
    let oldLocation = '';
    let newLocation = '';
    let findSeverityIndex;
    const codeSeverityCounter = [
        { severity: 'high', counter: 0 },
        { severity: 'medium', counter: 0 },
        { severity: 'low', counter: 0 },
    ];
    const rulesArray = dataArray[0].runs[0].tool.driver.rules;
    for (const issue of dataArray[0].runs[0].results) {
        issue.severitytext = codeSeverityMap[issue.level];
        findSeverityIndex = codeSeverityCounter.findIndex((f) => f.severity === issue.severitytext);
        codeSeverityCounter[findSeverityIndex].counter++;
        //add the code snippet here...
        issue.locations[0].physicalLocation.codeString = await readCodeSnippet(issue.locations[0]);
        //code stack
        for (const codeFlowLocations of issue.codeFlows[0].threadFlows[0].locations) {
            codeFlowLocations.location.physicalLocation.codeString = await readCodeSnippet(codeFlowLocations.location);
            newLocation =
                codeFlowLocations.location.physicalLocation.artifactLocation.uri;
            if (newLocation === oldLocation) {
                codeFlowLocations.location.physicalLocation.isshowfilename = false;
            }
            else {
                codeFlowLocations.location.physicalLocation.isshowfilename = true;
            }
            oldLocation = newLocation;
        }
        ;
        //find ruleId -> tool.driver.rules
        test = rulesArray.find((e) => e.id === issue.ruleId);
        issue.ruleiddesc = test;
    }
    ;
    const currentFolderPath = getCurrentDirectory();
    const OrderedIssuesArray = dataArray.map((project) => {
        return {
            details: project.runs[0].properties,
            sourceFilePath: currentFolderPath,
            vulnsummarycounter: codeSeverityCounter,
            vulnerabilities: orderBy(project.runs[0].results, ['properties.priorityScore'], ['desc']),
        };
    });
    return OrderedIssuesArray;
}
function getCurrentDirectory() {
    return process.cwd();
}
async function parse(data) {
    data = JSON.parse(data);
    let tf;
    tf = fs.readFileSync(path.resolve(__dirname, '../', 'sample.threadfix'), 'utf8');
    tf = JSON.parse(tf);
    const now = new Date().toISOString().replace(/\.\d\d\dZ/, 'Z');
    tf.created = now;
    tf.updated = now;
    tf.exported = now;
    tf.findings = [];
    const dataArray = Array.isArray(data) ? data : [data];
    let snykFindings = await processSourceCode(dataArray);
    snykFindings = snykFindings[0].vulnerabilities;
    snykFindings.forEach((res) => {
        let df = [];
        res.codeFlows[0].threadFlows[0].locations.forEach((loc) => {
            df.push({
                file: loc.location.physicalLocation.artifactLocation.uri,
                lineNumber: loc.location.physicalLocation.region.startLine,
                columnNumber: loc.location.physicalLocation.region.startColumn,
                text: `${loc.location.physicalLocation.codeString[0].codepremarker}${loc.location.physicalLocation.codeString[0].codemarker}${loc.location.physicalLocation.codeString[0].codepostmarker}`
            });
        });
        tf.findings.push({
            nativeId: res.fingerprints['0'],
            severity: tfSeverityMap[res.level],
            nativeSeverity: res.level,
            summary: res.ruleiddesc.shortDescription.text,
            description: res.message.text,
            scannerDetail: '',
            scannerRecommendation: res.ruleiddesc.help.markdown,
            staticDetails: {
                file: res.locations[0].physicalLocation.artifactLocation.uri,
                parameter: `line ${res.locations[0].physicalLocation.region.startLine}`,
                dataFlow: df
            }
        });
    });
    return tf;
}
try {
    const fin = process.argv[2];
    let snyk;
    snyk = fs.readFileSync(fin, 'utf8');
    const tf = await parse(snyk);
    fs.writeFileSync(`${fin.split('.')[0]}.threadfix`, JSON.stringify(tf));
}
catch (err) {
    console.error(err);
}
console.log('Done');
//# sourceMappingURL=index.js.map