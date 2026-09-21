/**
 * DOM ビルダー（小さなハイパースクリプト）。画面はすべてこれで組み立てる。
 *
 * - 文字列の子要素は必ずテキストノードとして挿入する。HTML として解釈される経路が存在しない（XSS 対策）。
 * - 属性は許可リスト方式。`on*` イベントハンドラ属性・`style`・`srcdoc`・任意の URL は設定できない。
 *   `href` は同一オリジンのパス（`/…`）とページ内リンク（`#…`）に限る。
 * - `setAttribute` を呼んでよいのはこのファイルだけ（tests/security-policy.test.ts が検査する）。
 *   利用者由来の値が属性へ流れる経路を、ここ 1 か所の許可リストに集約するため。
 */

export type Listener = (event: Event) => void;
export type Child = Node | string | number | null | undefined | false;
/** 子要素の並び。配列は何段入れ子になっていてもよい（append が再帰的に展開する）。 */
export type ChildList = Child | ReadonlyArray<ChildList>;
export type Children = ReadonlyArray<ChildList>;

export interface Props {
  [attribute: string]: string | number | boolean | null | undefined | Record<string, Listener>;
  on?: Record<string, Listener>;
}

const ALLOWED_ATTRIBUTES = new Set([
  'class', 'id', 'type', 'name', 'value', 'placeholder', 'rows', 'disabled', 'readonly', 'checked', 'hidden',
  'role', 'tabindex', 'title', 'for', 'accept', 'autocomplete', 'spellcheck', 'maxlength', 'multiple', 'required',
  'selected', 'href', 'lang',
]);
const ALLOWED_PATTERNS = [/^aria-[a-z]+$/, /^data-[a-z][a-z0-9-]*$/];

const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';
const ALLOWED_SVG_ATTRIBUTES = new Set([
  'viewBox', 'd', 'fill', 'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'width', 'height',
  'x', 'y', 'x1', 'x2', 'y1', 'y2', 'cx', 'cy', 'r', 'rx', 'ry', 'points', 'class', 'aria-hidden', 'focusable',
]);

export interface Dom {
  /** HTML 要素を作る。 */
  h<K extends keyof HTMLElementTagNameMap>(tag: K, props?: Props, ...children: Children): HTMLElementTagNameMap[K];
  /** SVG 要素を作る（アイコン用）。 */
  svg(tag: string, attributes?: Record<string, string>, ...children: Children): SVGElement;
  text(value: string): Text;
}

export function createDom(doc: Document): Dom {
  function append(parent: Node, children: Children): void {
    for (const child of children) {
      // as は、Array.isArray が readonly 配列を型として絞り込めない TypeScript の制約への対処（実行時の挙動は型どおり）
      if (Array.isArray(child)) append(parent, child as Children);
      else appendOne(parent, child as Child);
    }
  }

  function appendOne(parent: Node, child: Child): void {
    if (child === null || child === undefined || child === false) return;
    // 文字列・数値は常にテキストノード（HTML としては解釈されない）。realm をまたぐため instanceof は使わない。
    if (typeof child === 'string' || typeof child === 'number') parent.appendChild(doc.createTextNode(String(child)));
    else parent.appendChild(child);
  }

  function applyProps(element: HTMLElement, props: Props): void {
    for (const [name, value] of Object.entries(props)) {
      if (name === 'on') {
        for (const [type, listener] of Object.entries(value as Record<string, Listener>)) {
          element.addEventListener(type, listener);
        }
        continue;
      }
      if (value === null || value === undefined || value === false) continue;

      const allowed = ALLOWED_ATTRIBUTES.has(name) || ALLOWED_PATTERNS.some((pattern) => pattern.test(name));
      if (!allowed) throw new Error(`dom: attribute "${name}" is not allowed`);

      if (name === 'href') assertSafeHref(String(value));
      if (name === 'value') {
        (element as HTMLInputElement).value = String(value);
      } else {
        element.setAttribute(name, value === true ? '' : String(value));
      }
    }
  }

  return {
    h(tag, props = {}, ...children) {
      const element = doc.createElement(tag);
      applyProps(element, props);
      append(element, children);
      return element;
    },
    svg(tag, attributes = {}, ...children) {
      const element = doc.createElementNS(SVG_NAMESPACE, tag);
      for (const [name, value] of Object.entries(attributes)) {
        if (!ALLOWED_SVG_ATTRIBUTES.has(name)) throw new Error(`dom: svg attribute "${name}" is not allowed`);
        element.setAttribute(name, value);
      }
      append(element, children);
      return element;
    },
    text: (value) => doc.createTextNode(value),
  };
}

/** 同一オリジンのパス（`/x`、`//` は不可）とページ内リンク（`#x`）だけを許可する。`javascript:` などは通らない。 */
function assertSafeHref(href: string): void {
  if (!/^(\/(?!\/)[^\s]*|#[A-Za-z0-9_-]+)$/.test(href)) throw new Error('dom: href must be a same-origin path or a fragment');
}

/** 条件つきの class 連結。偽値は捨てる。 */
export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}
