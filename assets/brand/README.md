# Faro brand assets

*Faro* is Spanish and Italian for lighthouse. The mark is a lighthouse casting its light inside a circle, and the wordmark uses it as the "O" in FARO.

## Files

| File | Use |
|---|---|
| `faro-wordmark.svg` | Full logo. Headers, the README, the web app's sign-in page, installers |
| `faro-icon.svg` | The lighthouse mark alone. App and tray icons, favicons, small spaces |
| `faro-icon.icns` | The macOS app icon (16–1024 px). `installers/macos/build-pkg.sh` puts it in `Faro Agent.app` |

Both are vector files exported from the original artwork, with the path data unchanged. The web app imports them from here (`$brand/…` in `web/`) rather than keeping copies, so there is one set of logo files. The lighthouse is cut out of the circle rather than drawn in white, so it takes the colour of whatever is behind it. That works on both light and dark backgrounds.

## Colours

| Name | Hex | Used for |
|---|---|---|
| Faro amber | `#F19E4B` | The letters and the circle |
| Beam orange | `#ED7043` | The light beams |

Contrast ratios, for interface work:

| Colour | On white | On a dark background (`#0d1117`) |
|---|---|---|
| Faro amber | 2.2:1 | 8.8:1 |
| Beam orange | 3.0:1 | 6.3:1 |

Both are fine for the logo itself. On light backgrounds they are too low for body text or button labels (WCAG asks for 4.5:1), so interface text and controls there need a darker shade of the same hue. On dark backgrounds both colours are readable as text.

## Using the logo

The code is Apache-2.0, but that licence does not cover the Faro name or logo (see ARCHITECTURE.md §11). They identify official, project-signed builds, so that people can tell which installers came from the project.

- Instance operators may use the logo to say they run Faro, for example "Powered by Faro".
- Forks and modified builds should use their own name and logo.
- Don't recolour, stretch, or rearrange the mark. Keep clear space around it of at least the height of the lighthouse's lantern.
