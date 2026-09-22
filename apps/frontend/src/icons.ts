import type { Dom } from './dom.ts';

/** 24x24・線画のアイコン。装飾には使わず、状態（成功・警告）と実行中の表示にだけ使う。パスは固定の定数。 */
type Shape = readonly [tag: string, attributes: Record<string, string>];

const ICONS = {
  lock: [
    ['rect', { x: '3', y: '11', width: '18', height: '11', rx: '2' }],
    ['path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' }],
  ],
  check: [['path', { d: 'M20 6 9 17l-5-5' }]],
  alert: [
    ['path', { d: 'm21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3' }],
    ['path', { d: 'M12 9v4' }],
    ['path', { d: 'M12 17h.01' }],
  ],
  spinner: [['path', { d: 'M21 12a9 9 0 1 1-6.219-8.56' }]],
} as const satisfies Record<string, readonly Shape[]>;

export type IconName = keyof typeof ICONS;

export function createIcon(dom: Dom, name: IconName, className = 'size-4'): SVGElement {
  const shapes: readonly Shape[] = ICONS[name];
  return dom.svg(
    'svg',
    {
      viewBox: '0 0 24 24',
      fill: 'none',
      stroke: 'currentColor',
      'stroke-width': '2',
      'stroke-linecap': 'round',
      'stroke-linejoin': 'round',
      'aria-hidden': 'true',
      focusable: 'false',
      class: `shrink-0 ${className}`,
    },
    shapes.map(([tag, attributes]) => dom.svg(tag, attributes)),
  );
}
