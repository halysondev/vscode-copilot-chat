/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { ILogService } from '../../../../../platform/log/common/logService';
import { CancellationToken } from '../../../../../util/vs/base/common/cancellation';
import { claudeCodeOAuthManager } from '../../node/oauth';
import { IClaudeSlashCommandHandler, registerClaudeSlashCommand } from './claudeSlashCommandRegistry';

/**
 * Slash command handler for managing Claude Code OAuth authentication.
 *
 * Usage:
 * - /auth status - Show current authentication status
 * - /auth login  - Start OAuth login flow
 * - /auth logout - Clear stored credentials
 */
export class AuthSlashCommand implements IClaudeSlashCommandHandler {
	readonly commandName = 'auth';
	readonly description = 'Manage Claude Code authentication (login, logout, status)';
	readonly commandId = 'copilot.claude.auth';

	constructor(
		@ILogService private readonly logService: ILogService,
	) { }

	async handle(
		args: string,
		stream: vscode.ChatResponseStream | undefined,
		_token: CancellationToken
	): Promise<vscode.ChatResult> {
		const subcommand = args.trim().toLowerCase();

		switch (subcommand) {
			case 'login':
				return this._handleLogin(stream);
			case 'logout':
				return this._handleLogout(stream);
			case 'status':
			default:
				return this._handleStatus(stream);
		}
	}

	private async _handleLogin(stream?: vscode.ChatResponseStream): Promise<vscode.ChatResult> {
		try {
			const isAuthenticated = await claudeCodeOAuthManager.isAuthenticated();
			if (isAuthenticated) {
				const email = await claudeCodeOAuthManager.getEmail();
				stream?.markdown(vscode.l10n.t('Already authenticated as **{0}**.\n\nUse `/auth logout` to sign out.', email || 'Claude Code user'));
				return {};
			}

			stream?.markdown(vscode.l10n.t('Starting authentication...\n\nOpening browser for OAuth login...'));

			const authUrl = claudeCodeOAuthManager.startAuthorizationFlow();
			await vscode.env.openExternal(vscode.Uri.parse(authUrl));

			try {
				await claudeCodeOAuthManager.waitForCallback();
				const email = await claudeCodeOAuthManager.getEmail();

				vscode.window.showInformationMessage(
					vscode.l10n.t('Claude Code: Authenticated as {0}', email || 'Claude Code user')
				);

				stream?.markdown(vscode.l10n.t('\n\n✓ **Authenticated successfully** as {0}', email || 'Claude Code user'));
			} catch (callbackError) {
				this.logService.error('[AuthSlashCommand] OAuth callback error:', callbackError);
				stream?.markdown(vscode.l10n.t('\n\n✗ Authentication failed: {0}', callbackError instanceof Error ? callbackError.message : String(callbackError)));
			}
		} catch (error) {
			this.logService.error('[AuthSlashCommand] Login error:', error);
			stream?.markdown(vscode.l10n.t('Error starting authentication: {0}', error instanceof Error ? error.message : String(error)));
		}

		return {};
	}

	private async _handleLogout(stream?: vscode.ChatResponseStream): Promise<vscode.ChatResult> {
		try {
			const isAuthenticated = await claudeCodeOAuthManager.isAuthenticated();
			if (!isAuthenticated) {
				stream?.markdown(vscode.l10n.t('Not currently authenticated.'));
				return {};
			}

			await claudeCodeOAuthManager.clearCredentials();

			vscode.window.showInformationMessage(vscode.l10n.t('Claude Code: Logged out'));
			stream?.markdown(vscode.l10n.t('✓ Logged out successfully.\n\nUse `/auth login` to authenticate again.'));
		} catch (error) {
			this.logService.error('[AuthSlashCommand] Logout error:', error);
			stream?.markdown(vscode.l10n.t('Error logging out: {0}', error instanceof Error ? error.message : String(error)));
		}

		return {};
	}

	private async _handleStatus(stream?: vscode.ChatResponseStream): Promise<vscode.ChatResult> {
		try {
			const isAuthenticated = await claudeCodeOAuthManager.isAuthenticated();

			if (!isAuthenticated) {
				stream?.markdown(vscode.l10n.t('**Status**: Not authenticated\n\nUse `/auth login` to authenticate with Claude Code.'));
				return {};
			}

			const email = await claudeCodeOAuthManager.getEmail();
			let statusMessage = vscode.l10n.t('**Status**: Authenticated\n\n**Email**: {0}\n', email || 'Unknown');

			// Note: Rate limit info could be added here by making a test API call
			// For now, we just show auth status
			statusMessage += vscode.l10n.t('\nUse `/auth logout` to sign out.');

			stream?.markdown(statusMessage);
		} catch (error) {
			this.logService.error('[AuthSlashCommand] Status error:', error);
			stream?.markdown(vscode.l10n.t('Error checking status: {0}', error instanceof Error ? error.message : String(error)));
		}

		return {};
	}
}

// Self-register the auth command
registerClaudeSlashCommand(AuthSlashCommand);
