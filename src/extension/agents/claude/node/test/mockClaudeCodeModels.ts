/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ClaudeCodeReasoningLevel } from '../claude-code';
import { ClaudeCodeModelInfo, IClaudeCodeModels } from '../claudeCodeModels';

export class MockClaudeCodeModels implements IClaudeCodeModels {
	declare _serviceBrand: undefined;

	private _defaultModel: string | undefined = 'claude-sonnet-4-20250514';
	private _reasoningEffort: ClaudeCodeReasoningLevel = 'high';

	async resolveModel(modelId: string): Promise<string | undefined> {
		const models = await this.getModels();
		const normalizedId = modelId.trim().toLowerCase();
		return models.find(m => m.id.toLowerCase() === normalizedId || m.name.toLowerCase() === normalizedId)?.id;
	}

	async getDefaultModel(): Promise<string | undefined> {
		return this._defaultModel;
	}

	async setDefaultModel(modelId: string | undefined): Promise<void> {
		this._defaultModel = modelId;
	}

	async getModels(): Promise<ClaudeCodeModelInfo[]> {
		return [
			{ id: 'claude-sonnet-4-20250514', name: 'Claude Sonnet 4' },
			{ id: 'claude-opus-4-20250514', name: 'Claude Opus 4' },
			{ id: 'claude-haiku-3-5-20250514', name: 'Claude Haiku 3.5' },
			{ id: 'claude-opus-4-5-20251101', name: 'Claude Opus 4.5' },
		];
	}

	getReasoningEffort(): ClaudeCodeReasoningLevel {
		return this._reasoningEffort;
	}

	async setReasoningEffort(level: ClaudeCodeReasoningLevel): Promise<void> {
		this._reasoningEffort = level;
	}

	getReasoningEffortOptions(): { id: ClaudeCodeReasoningLevel; name: string; description: string }[] {
		return [
			{ id: 'disable', name: 'Disable', description: 'No thinking' },
			{ id: 'low', name: 'Low', description: '16,000 tokens' },
			{ id: 'medium', name: 'Medium', description: '32,000 tokens' },
			{ id: 'high', name: 'High', description: '64,000 tokens' },
		];
	}
}
