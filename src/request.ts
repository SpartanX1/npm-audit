import { promisify } from 'util';
import { Uri, window, ViewColumn } from 'vscode';
import { dirname, join } from 'path';
import { Report, Advisory } from './report.model';
import { render } from 'mustache';
import { readFile } from 'fs-extra';


export async function getAudit(resource: Uri): Promise<any> {
    const exec = promisify(require('child_process').exec);

    try {
        let result = await exec('npm audit --json --prefix ' 
        + (process.platform !== 'win32'? '/': '') + dirname(resource.path.substring(1)), { windowsHide: true });
        return JSON.parse(result.stdout)
    }
    catch (output) {
        if (output.stderr.length > 0) {
            return Promise.reject(output.stderr);
        }
        return JSON.parse(output.stdout)
    }
}

export async function createHTMLReport(data: Report): Promise<void> {

    const panel = window.createWebviewPanel('auditReport', 'Audit Report', ViewColumn.One,
        {
            localResourceRoots: []
        }
    );

    const template = await readFile(join(__dirname, `assets/templates/output.mustache`), 'utf8');

    const view = {
        criticalCount: data.metadata.vulnerabilities.critical,
        highCount: data.metadata.vulnerabilities.high,
        moderateCount: data.metadata.vulnerabilities.moderate,
        lowCount: data.metadata.vulnerabilities.low,
        infoCount: data.metadata.vulnerabilities.info
    }

    let content = render(template, view);

    content += addSubHeader(data);

    content += '<h3>Advisories</h3>';

    content += addAdvTable(data);

    content += '<br>' + '<h3>Recommendations</h3>';
    content += `<span style="margin-left:5px;margin-bottom: 10px" class="badge badge-moderate">M</span> = Major Upgrade, Semver breaking 
    change ! <a href="https://semver.org/">Learn More</a>` + addActionsTable(data);

    content += '<div style="display: flex; justify-content: space-around;"><div>--- end-of-report ---<div></div><br>'

    panel.webview.html = content;
}

function addSubHeader(data: Report): string {
    return `<div>Found <b>${data.metadata.vulnerabilities.critical
        + data.metadata.vulnerabilities.high
        + data.metadata.vulnerabilities.moderate
        + data.metadata.vulnerabilities.low
        + data.metadata.vulnerabilities.info
        }</b> vulnerabilities in <b>${data.metadata.totalDependencies}</b> scanned packages.</div>`;
}

function addAdvTable(data: Report): string {

    let advTable = `<table>
    <tr>
      <th>Id</th>
      <th>Title</th>
      <th>Module</th>
      <th>Severity</th>
      <th>Last Updated</th>
      <th>Affected Versions</th>
      <th>Patched Versions</th>
    </tr>`;


    advTable += parseAdvisories(data) + '</table>';

    return advTable;
}

function addActionsTable(data: Report) {

    let actionTable = `<table>
    <tr>
      <th>Action</th>
      <th>Module</th>
      <th>Dependency In</th>
      <th>Advisories</th>
      <th>Resolves</th>
    </tr>`;

    actionTable += parseActions(data) + '</table>';

    return actionTable;
}


function parseAdvisories(data: Report) {

    let count = 0;
    let rows = '';

    Object.values(data.advisories).forEach(advisory => {
        const item = advisory as Advisory;
        rows += '<tr>'
        rows += '<td><a name="' + item.id + '" href="' + item.url + '"' + `>${item.id}</a></td>`;
        rows += `<td>${item.title}</td>`;
        rows += `<td><b>${item.module_name}</b></td>`;

        switch (item.severity) {
            case 'low': rows += `<td><span class="badge badge-low">${item.severity}</span></td>`; break;
            case 'moderate': rows += `<td><span class="badge badge-moderate">${item.severity}</span></td>`; break;
            case 'high': rows += `<td><span class="badge badge-high">${item.severity}</span></td>`; break;
            case 'critical': rows += `<td><span class="badge badge-critical">${item.severity}</span></td>`; break;
            case 'info': rows += `<td><span class="badge badge-info">${item.severity}</span></td>`; break;
            default: rows += '<td>Unknown</td>';
        }

        rows += `<td>${new Date(item.updated).toLocaleDateString()}</td>`;
        rows += `<td>${item.vulnerable_versions}</td>`;
        rows += `<td>${item.patched_versions}</td>`;
    });

    return rows;
}

function parseActions(data: Report) {

    let rows = '';

    data.actions.forEach(item => {
        rows += '<tr>'

        switch (item.action) {
            case 'review': {
                rows += '<td>Requires manual review</td>';
            } break;
            case 'update': {
                rows += `<td><span class="badge badge-action"> npm ${item.action}`
                    + ` ${item.module}`
                    + ` --depth ${item.depth}`
                    + '</span></td>';
            } break;
            case 'install': {
                rows += `<td><span class="badge badge-action"> npm ${item.action}`
                    + ` ${item.module}` + `@${item.target}`
                    + ` --save`
                    + `${item.resolves[0].dev == true ? '-dev ' : ' '}`
                    + '</span></td>';
            } break;
            default: {
                rows += '';
            } break;
        }

        rows += `<td><b>${item.module}</b>` + `${item.isMajor == true ? '<span style="margin-left:5px;" class="badge badge-moderate">M</span>' : ''}` + `</td>`;

        let advColumn = '<td style="white-space:pre;">';

        let dependencyColumn = '<td style="white-space:pre;">';

        let advisories: number[] = [];
        item.resolves.forEach((resolve) => {
            if (!advisories.includes(resolve.id)) {
                advisories.push(resolve.id);
                
                advColumn += '<a href="' + data.advisories[resolve.id].url + '"' + `>${resolve.id}</a> - ${data.advisories[resolve.id].title}` + '\n';

                dependencyColumn += `<span class ="badge badge-module">${data.advisories[resolve.id].module_name}</span>` + '\n';
            }
        })

        rows += dependencyColumn + '</td>' + advColumn + '</td>';

        rows += `<td><b>${item.resolves.length}</b> vulnerabilities</td></tr>`;
    });

    return rows;
}
