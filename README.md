# rabi-central-admin

Central administration for [rabsrabi.com](https://rabsrabi.com) and **rabsrabi / notes** ([blog.rabsrabi.com](https://blog.rabsrabi.com)), served at auth.rabsrabi.com.

- Sign-in: GitHub OAuth, restricted to one allowed account (`GITHUB_ALLOWED_LOGIN`).
- Dashboard: links to the notes editor today; the portfolio tools are marked "Coming soon".
- Look: the shared rabsrabi brand. A copy of the brand kit (v1) is in `assets/brand/`, from <https://github.com/rabsrabi26/brand>. Do not edit those two files here; update them by copying from that repository. Page styles are in `admin.css`.

Configuration lives outside the web root in `../private/config.php` and is never committed.
