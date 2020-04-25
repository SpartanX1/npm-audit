import { commands, ExtensionContext, window, Uri, ProgressLocation } from 'vscode';
import { getAudit, createHTMLReport } from './request';

export function activate(context: ExtensionContext) {

	let disposable = commands.registerCommand('extension.onAudit', (resource: Uri) => {
		window.withProgress({
			location: ProgressLocation.Notification,
			title: 'Running NPM audit ...',
			cancellable: false
		}, async () => {
			try {
					const result = await getAudit(resource);
					createHTMLReport(result);
				}
				catch (err) {
					window.showErrorMessage(err);
				} 
		});
	});

	context.subscriptions.push(disposable);
}

export function deactivate() {}