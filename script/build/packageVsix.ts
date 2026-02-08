/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

const pkgPath = path.resolve(__dirname, '../../package.json');
const original = fs.readFileSync(pkgPath, 'utf-8');

try {
	const pkg = JSON.parse(original);

	// Strip @version suffixes from enabledApiProposals
	if (Array.isArray(pkg.enabledApiProposals)) {
		pkg.enabledApiProposals = pkg.enabledApiProposals.map((p: string) => p.replace(/@\d+$/, ''));
	}

	// Generate a timestamp-based version: 0.38.YYYYMMDHH
	const now = new Date();
	const y = now.getFullYear();
	const m = String(now.getMonth() + 1).padStart(2, '0');
	const d = String(now.getDate()).padStart(2, '0');
	const h = String(now.getHours()).padStart(2, '0');
	pkg.version = `0.38.${y}${m}${d}${h}`;

	fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, '\t') + '\n', 'utf-8');
	console.log(`Version set to ${pkg.version}`);
	console.log('Stripped @version suffixes from enabledApiProposals');

	// Run vsce package
	execSync('npx @vscode/vsce package --no-dependencies --skip-license', {
		stdio: 'inherit',
		cwd: path.resolve(__dirname, '../..'),
	});
} finally {
	// Always restore original package.json
	fs.writeFileSync(pkgPath, original, 'utf-8');
	console.log('Restored original package.json');
}
