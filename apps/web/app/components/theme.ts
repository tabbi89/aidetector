// Shared by the server layout (boot script) and the client toggle, so this
// module must stay free of React and "use client".

export type Theme = "light" | "dark";
export const DEFAULT_THEME: Theme = "dark";

/** Where the reader's choice is stored. */
export const THEME_KEY = "aidetector-theme";

/** Browser-chrome colour per theme: each theme's `--paper` in globals.css. */
export const THEME_COLOR: Record<Theme, string> = {
  light: "#ffffff",
  dark: "#0e1116",
};

/**
 * Applies a stored theme before first paint so a dark-mode reader never sees a
 * light flash. No stored choice means dark — the OS preference is not read.
 *
 * The theme-color meta is created here instead of declared through Next's
 * `viewport`: this script and the toggle both repaint it, and a tag React
 * renders would not match what hydration expects.
 */
export const BOOT_THEME = `(function(){var t=${JSON.stringify(DEFAULT_THEME)};try{var s=localStorage.getItem(${JSON.stringify(THEME_KEY)});if(s==="light"||s==="dark")t=s}catch(e){}document.documentElement.dataset.theme=t;var m=document.createElement("meta");m.name="theme-color";m.content=${JSON.stringify(THEME_COLOR)}[t];document.head.appendChild(m)})();`;

/** Repaints the browser chrome for `theme`, creating the meta if it is missing. */
export function paintThemeColor(theme: Theme) {
  let meta = document.querySelector<HTMLMetaElement>(
    'meta[name="theme-color"]',
  );
  if (!meta) {
    meta = document.createElement("meta");
    meta.name = "theme-color";
    document.head.appendChild(meta);
  }
  meta.content = THEME_COLOR[theme];
}
