// Packaging invariants.
//
// Three files decide whether a profile can load this plugin, and all three must
// agree on one identifier:
//
//   package.json      -> "name" is the specifier the profile resolves the host half by
//   cordis.patch.yml  -> the insert row's "name" is that same specifier
//   client.js         -> __ModuleLoader__.load({ id }) must equal it, or the
//                        browser half registers under an id nobody asked for
//
// A mismatch is silent for the host half ("Cannot find package") and silent for
// the browser half ("loaded without registering"), and both surface as the same
// user-visible symptom: the plugin claims it installed, then does nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const read = (name) => readFileSync(path.join(root, name), 'utf8');
const pkg = JSON.parse(read('package.json'));

const unquote = (value) => value.trim().replace(/^['"]|['"]$/g, '');

/** Pull the "insert" rows of cordis.patch.yml, keeping only their id and name. */
function insertRows(text) {
  const rows = [];
  let current;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '');
    if (/^\s*-\s+id:/.test(line)) {
      if (current) rows.push(current);
      current = { id: unquote(line.slice(line.indexOf(':') + 1)) };
      continue;
    }
    if (current && /^\s+name:/.test(line)) current.name = unquote(line.slice(line.indexOf(':') + 1));
  }
  if (current) rows.push(current);
  return rows;
}

test('cordis.patch.yml 的 insert 行按包名加载，而不是包名去掉 scope 后的短名', () => {
  const rows = insertRows(read('cordis.patch.yml'));
  assert.ok(rows.length > 0, 'cordis.patch.yml 里没有 insert 行');
  for (const row of rows) {
    assert.equal(
      row.name,
      pkg.name,
      `insert 行 "${row.id}" 的 name 是 "${row.name}"，但包名是 "${pkg.name}"；profile 会按这个 specifier 解析，短名解析不到会让整个插件激活失败`,
    );
  }
});

test('client.js 注册的模块 id 等于包名', () => {
  const match = read('client.js').match(/__ModuleLoader__\.load\(\s*\{\s*id:\s*['"]([^'"]+)['"]/);
  assert.ok(match, 'client.js 里没有找到 __ModuleLoader__.load({ id })');
  assert.equal(
    match[1],
    pkg.name,
    `client.js 的模块 id 是 "${match[1]}"，包名是 "${pkg.name}"；host 按包名请求这个 bundle，id 对不上会报 loaded without registering`,
  );
});

test('exports 暴露 ./package.json', () => {
  assert.equal(
    pkg.exports?.['./package.json'],
    './package.json',
    '缺少 "./package.json" 导出：client-modules 解析归属包时会 require.resolve("<包名>/package.json")',
  );
});

test('dsh.client.inject 覆盖 client.js 实际用到的宿主服务', () => {
  const inject = pkg.dsh?.client?.inject ?? [];
  const source = read('client.js');
  const needs = [
    ['@deepseek-ai/dsh-client-locale', /ctx\.locale\b/],
    ['@deepseek-ai/dsh-client-ui-settings', /settings\.section/],
  ];
  for (const [dep, used] of needs) {
    if (used.test(source)) assert.ok(inject.includes(dep), `client.js 用到 ${dep}，但 dsh.client.inject 没有声明`);
  }
});