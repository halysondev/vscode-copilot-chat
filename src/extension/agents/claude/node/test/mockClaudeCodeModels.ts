/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IEndpointProvider } from '../../../../../platform/endpoint/common/endpointProvider';
import { IVSCodeExtensionContext } from '../../../../../platform/extContext/common/extensionContext';
import { ILogService } from '../../../../../platform/log/common/logService';
import { ClaudeCodeReasoningLevel, isOpus46Model } from '../claude-code';
import { ClaudeCodeModelInfo, ClaudeCodeModels } from '../claudeCodeModels';

export class MockClaudeCodeModels extends ClaudeCodeModels {
	private _reasoningEffort: ClaudeCodeReasoningLevel = 'high';

	constructor(
		@IEndpointProvider endpointProvider: IEndpointProvider,
		@IVSCodeExtensionContext extensionContext: IVSCodeExtensionContext,
		@ILogService logService: ILogService,
	) {
		super(endpointProvider, extensionContext, logService);
	}

	override async getModels(): Promise<ClaudeCodeModelInfo[]> {
		return [
			{ id: 'claude-sonnet-4-20250514', name: 'Claude Sonnet 4' },
			{ id: 'claude-opus-4-20250514', name: 'Claude Opus 4' },
			{ id: 'claude-haiku-3-5-20250514', name: 'Claude Haiku 3.5' },
			{ id: 'claude-opus-4-5-20251101', name: 'Claude Opus 4.5' },
			{ id: 'claude-opus-4-6', name: 'Claude Opus 4.6' },
		];
	}

	override getReasoningEffort(): ClaudeCodeReasoningLevel {
		return this._reasoningEffort;
	}

	override async setReasoningEffort(level: ClaudeCodeReasoningLevel): Promise<void> {
		this._reasoningEffort = level;
	}

	override getReasoningEffortOptions(modelId?: string): { id: ClaudeCodeReasoningLevel; name: string; description: string }[] {
		const options: { id: ClaudeCodeReasoningLevel; name: string; description: string }[] = [
			{ id: 'disable', name: 'Disable', description: 'No thinking' },
			{ id: 'low', name: 'Low', description: '16,000 tokens' },
			{ id: 'medium', name: 'Medium', description: '32,000 tokens' },
			{ id: 'high', name: 'High', description: '64,000 tokens' },
		];

		if (modelId && isOpus46Model(modelId)) {
			options.push({ id: 'max', name: 'Max', description: 'Maximum thinking (Opus 4.6 only)' });
		}

		return options;
	}
}
