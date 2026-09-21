/* 保存済みのテーマ選択を、最初の描画より前に適用する（チラつき防止）。未選択ならシステム設定に従う（CSS 側）。 */
(function () {
  try {
    var stored = localStorage.getItem('cipherdrop-theme');
    if (stored === 'light' || stored === 'dark') document.documentElement.dataset.theme = stored;
  } catch (error) {
    /* localStorage が使えない環境（プライベートモード等）では、システム設定のままにする */
  }
})();
