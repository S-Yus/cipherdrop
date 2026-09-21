import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { JSDOM } from 'jsdom';
import { createDom, cx } from './dom.ts';

function setup() {
  const { window } = new JSDOM('<!doctype html><html><body></body></html>');
  return { window, dom: createDom(window.document) };
}

describe('createDom: 子要素は常にテキストノード（HTML として解釈されない）', () => {
  it('HTML を含む文字列は要素にならず、文字のまま表示される', () => {
    const { dom } = setup();
    const attack = '<img src=x onerror="alert(1)"><script>alert(2)</script>&lt;b&gt;';
    const element = dom.h('div', {}, attack);

    assert.equal(element.children.length, 0, '子要素は 1 つも生成されない');
    assert.equal(element.childNodes.length, 1);
    assert.equal(element.firstChild?.nodeType, 3, 'TEXT_NODE');
    assert.equal(element.textContent, attack);
  });

  it('数値はテキスト、null / undefined / false は無視、入れ子の配列は展開される', () => {
    const { dom } = setup();
    const element = dom.h('p', {}, 'a', 1, null, undefined, false, ['b', ['c']], dom.h('span', {}, 'd'));
    assert.equal(element.textContent, 'a1bcd');
    assert.equal(element.querySelectorAll('span').length, 1);
  });
});

describe('createDom: 属性は許可リスト方式', () => {
  it('許可された属性・aria-* ・data-* は設定できる', () => {
    const { dom } = setup();
    const element = dom.h('button', { type: 'button', class: 'a b', id: 'x', 'aria-label': '説明', 'data-action': 'go', tabindex: -1, title: 't' });
    assert.equal(element.getAttribute('type'), 'button');
    assert.equal(element.className, 'a b');
    assert.equal(element.getAttribute('aria-label'), '説明');
    assert.equal(element.dataset['action'], 'go');
    assert.equal(element.getAttribute('tabindex'), '-1');
  });

  it('真偽値の属性: true は付き、false / null / undefined は付かない', () => {
    const { dom } = setup();
    const on = dom.h('input', { disabled: true, readonly: true });
    const off = dom.h('input', { disabled: false, readonly: null, hidden: undefined });
    assert.equal(on.hasAttribute('disabled') && on.hasAttribute('readonly'), true);
    assert.equal(off.hasAttribute('disabled') || off.hasAttribute('readonly') || off.hasAttribute('hidden'), false);
  });

  it('value は入力欄のプロパティとして設定される（textarea でも効く）', () => {
    const { dom } = setup();
    assert.equal(dom.h('textarea', { value: '<b>x</b>' }).value, '<b>x</b>');
    assert.equal(dom.h('input', { type: 'text', value: 'abc' }).value, 'abc');
  });

  it('イベントハンドラ属性・style・srcdoc・src・formaction・任意の属性は、名前だけで拒否される', () => {
    const { dom } = setup();
    const forbidden = ['onclick', 'onerror', 'onload', 'onmouseover', 'style', 'srcdoc', 'src', 'formaction', 'action', 'xlink:href', 'innerHTML', 'data-Bad', 'aria-', 'is'];
    for (const name of forbidden) {
      assert.throws(() => dom.h('div', { [name]: 'x' }), /not allowed/, name);
    }
  });

  it('href は同一オリジンのパスとページ内リンクだけ。javascript: や外部 URL は拒否する', () => {
    const { dom } = setup();
    for (const ok of ['/', '/v/abc', '#main', '#a-b_c']) assert.equal(dom.h('a', { href: ok }).getAttribute('href'), ok);
    for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'https://evil.example', '//evil.example', ' /x', 'data:text/html,<script>', 'vbscript:x', '', '#', '/x y']) {
      assert.throws(() => dom.h('a', { href: bad }), /href/, JSON.stringify(bad));
    }
  });

  it('on: { click } のリスナーが呼ばれる', () => {
    const { dom, window } = setup();
    let clicks = 0;
    const button = dom.h('button', { on: { click: () => void clicks++ } });
    button.dispatchEvent(new window.MouseEvent('click'));
    assert.equal(clicks, 1);
  });
});

describe('createDom: SVG', () => {
  it('SVG 名前空間の要素を作れ、許可された属性だけ設定できる', () => {
    const { dom } = setup();
    const svg = dom.svg('svg', { viewBox: '0 0 24 24', class: 'size-5' }, dom.svg('path', { d: 'M0 0h24' }));
    assert.equal(svg.namespaceURI, 'http://www.w3.org/2000/svg');
    assert.equal(svg.firstElementChild?.namespaceURI, 'http://www.w3.org/2000/svg');
    for (const name of ['onload', 'href', 'style', 'xlink:href']) {
      assert.throws(() => dom.svg('svg', { [name]: 'x' }), /not allowed/, name);
    }
  });
});

describe('cx', () => {
  it('偽値を捨てて class を連結する', () => {
    assert.equal(cx('a', false, null, undefined, 'b', '', 'c'), 'a b c');
  });
});
