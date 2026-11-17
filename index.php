<?php
require_once __DIR__ . '/../private/config.php';

session_name(SESSION_NAME);
session_start();
// Database connection
$pdo = new PDO(
    'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
    DB_USER,
    DB_PASS,
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]
);
// Secure logout
if (($_GET['route'] ?? '') === 'logout') {
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();

    header('Location: ' . APP_URL . '/');
    exit;
}
if (($_GET['route'] ?? '') === 'login') {

    $state = bin2hex(random_bytes(32));

    $_SESSION['oauth_state'] = $state;

    $params = [
        'client_id' => GITHUB_CLIENT_ID,
        'redirect_uri' => APP_URL . '/callback',
        'scope' => 'read:user',
        'state' => $state
    ];

    $githubUrl = 'https://github.com/login/oauth/authorize?' .
        http_build_query($params);

    header('Location: ' . $githubUrl);
    exit;
}

if (($_GET['route'] ?? '') === 'callback') {

    try {
        $code = $_GET['code'] ?? '';
        $state = $_GET['state'] ?? '';

        if (
            $code === '' ||
            $state === '' ||
            empty($_SESSION['oauth_state']) ||
            !hash_equals($_SESSION['oauth_state'], $state)
        ) {
            throw new RuntimeException('Invalid OAuth state.');
        }

        unset($_SESSION['oauth_state']);

        // Exchange authorization code for access token
        $ch = curl_init('https://github.com/login/oauth/access_token');

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'client_id' => GITHUB_CLIENT_ID,
                'client_secret' => GITHUB_CLIENT_SECRET,
                'code' => $code,
                'redirect_uri' => APP_URL . '/callback'
            ]),
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'User-Agent: Rabi-Central-Admin'
            ],
            CURLOPT_TIMEOUT => 20
        ]);

        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false || $status !== 200) {
            throw new RuntimeException('GitHub token exchange failed.');
        }

        $tokenData = json_decode($response, true);

        if (empty($tokenData['access_token'])) {
            throw new RuntimeException('GitHub access token missing.');
        }

        // Retrieve GitHub account
        $ch = curl_init('https://api.github.com/user');

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Accept: application/vnd.github+json',
                'Authorization: Bearer ' . $tokenData['access_token'],
                'User-Agent: Rabi-Central-Admin'
            ],
            CURLOPT_TIMEOUT => 20
        ]);

        $userResponse = curl_exec($ch);
        $userStatus = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($userResponse === false || $userStatus !== 200) {
            throw new RuntimeException('Could not retrieve GitHub account.');
        }

        $user = json_decode($userResponse, true);

        if (($user['login'] ?? '') !== GITHUB_ALLOWED_LOGIN) {
            throw new RuntimeException('Unauthorized GitHub account.');
        }

        session_regenerate_id(true);

        $_SESSION['authenticated'] = true;
        $_SESSION['github_login'] = $user['login'];
        $_SESSION['github_name'] = $user['name'] ?? $user['login'];

        header('Location: ' . APP_URL . '/');
        exit;

    } catch (Throwable $e) {
        error_log('Central Admin callback: ' . $e->getMessage());
        http_response_code(400);
        render_message('Sign-in failed', 'GitHub sign-in failed', 'Please check the server error log, then try again.');
        exit;
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

function e($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function render_head(string $title): void
{
    ?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="robots" content="noindex,nofollow">
    <meta name="theme-color" content="#F3F6FA" media="(prefers-color-scheme: light)">
    <meta name="theme-color" content="#080D17" media="(prefers-color-scheme: dark)">
    <title><?= e($title) ?> &middot; rabsrabi admin</title>
    <link rel="icon" href="/favicon.svg" type="image/svg+xml">
    <link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png">
    <link rel="apple-touch-icon" href="/apple-touch-icon.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@500;600;700;800&amp;family=Instrument+Sans:wght@400;500;600;700&amp;family=JetBrains+Mono:wght@400;500;600&amp;display=swap">
    <link rel="stylesheet" href="/assets/brand/brand.css">
    <link rel="stylesheet" href="/admin.css">
    <script src="/assets/brand/brand.js"></script>
</head>
<body>
    <a class="skip" href="#main">Skip to content</a>
<?php
}

function render_header(bool $signedIn): void
{
    ?>
    <header class="site-head">
        <div class="wrap head-in">
            <a class="lockup" href="/" aria-label="rabsrabi admin, home">
                <svg class="mark" aria-hidden="true"><use href="#rs-mark"/></svg>
                <span class="wm">rabs<i>rabi</i></span>
                <span class="sub">/ admin</span>
            </a>
<?php if ($signedIn): ?>
            <nav class="head-nav" aria-label="Main navigation">
                <a href="/" aria-current="page">Dashboard</a>
                <a href="https://blog.rabsrabi.com/admin/">Notes editor</a>
            </nav>
<?php endif; ?>
            <div class="head-end">
<?php if ($signedIn): ?>
                <button type="button" class="btn" data-palette-open style="min-height:36px;padding:0 12px;font-size:12px" aria-label="Open command palette"><span aria-hidden="true">&#8981;</span><span class="hide-sm">Search</span><kbd class="hide-sm">Ctrl K</kbd></button>
<?php endif; ?>
                <div class="seg" role="group" aria-label="Theme">
                    <button type="button" data-theme-choice="auto" aria-pressed="true">Auto</button>
                    <button type="button" data-theme-choice="light" aria-pressed="false">Light</button>
                    <button type="button" data-theme-choice="dark" aria-pressed="false">Dark</button>
                </div>
<?php if ($signedIn): ?>
                <a class="btn quiet hide-sm" style="min-height:36px" href="?route=logout">Sign out</a>
<?php endif; ?>
            </div>
        </div>
    </header>
<?php
}

function render_footer(bool $signedIn = false): void
{
    ?>
    <footer class="site-foot">
        <div class="wrap">
            <a class="lockup" href="/" aria-label="rabsrabi admin, home"><svg class="mark" style="width:26px;height:26px" aria-hidden="true"><use href="#rs-mark"/></svg><span class="wm" style="font-size:17px">rabs<i>rabi</i></span><span class="sub">/ admin</span></a>
<?php if ($signedIn): ?>
            <a class="links" href="?route=logout" style="color:var(--ink)">Sign out</a>
<?php endif; ?>
            <span class="copy">&copy; <?= date('Y') ?> Rabiul Islam</span>
        </div>
    </footer>
</body>
</html>
<?php
}

/** A short centered message, used for the sign-in page and for errors. */
function render_message(string $title, string $heading, string $text, ?string $buttonHref = null, ?string $buttonLabel = null, ?string $note = null): void
{
    http_response_code($buttonHref === null ? 400 : 200);
    render_head($title);
    render_header(false);
    ?>
    <main id="main" class="wrap">
        <section class="panel">
            <div class="eyebrow">Private workspace</div>
            <h1><?= e($heading) ?></h1>
            <p><?= e($text) ?></p>
<?php if ($note !== null): ?>
            <p class="hint"><?= e($note) ?></p>
<?php endif; ?>
<?php if ($buttonHref !== null): ?>
            <a class="btn primary" href="<?= e($buttonHref) ?>"><?= e($buttonLabel) ?></a>
<?php else: ?>
            <a class="btn" href="/">Back to sign in</a>
<?php endif; ?>
        </section>
    </main>
<?php
    render_footer();
}

// ---------------------------------------------------------------------------
// Signed in: dashboard
// ---------------------------------------------------------------------------

if (!empty($_SESSION['authenticated'])) {
    $name  = $_SESSION['github_name'] ?? 'Administrator';
    $login = $_SESSION['github_login'] ?? '';

    render_head('Dashboard');
    render_header(true);
    ?>
    <main id="main" class="wrap dash">
        <section class="dash-head">
            <div>
                <div class="eyebrow">Central admin</div>
                <h1>Welcome, <?= e($name) ?></h1>
                <p class="muted">Signed in as <span class="mono"><?= e($login) ?></span></p>
            </div>
            <span class="tag"><span class="dot"></span>Signed in</span>
        </section>

        <section class="grid dash-grid" aria-label="Sites and tools">
            <a class="card" href="https://blog.rabsrabi.com/admin/">
                <div class="top"><span class="tag">Live</span><span>blog.rabsrabi.com</span></div>
                <h4>Notes editor</h4>
                <p>Write, edit and publish posts on rabsrabi notes.</p>
                <div class="bottom"><span>Opens in the blog</span><span class="go">Open editor &rarr;</span></div>
            </a>
            <article class="card">
                <div class="top"><span class="tag plain">Portfolio</span><span class="tag spark">Coming soon</span></div>
                <h4>Portfolio management</h4>
                <p>Manage your personal portfolio website.</p>
                <div class="bottom"><span>rabsrabi.com</span></div>
            </article>
            <article class="card">
                <div class="top"><span class="tag plain">Portfolio</span><span class="tag spark">Coming soon</span></div>
                <h4>Projects &amp; research</h4>
                <p>Manage projects, publications and research.</p>
                <div class="bottom"><span>rabsrabi.com</span></div>
            </article>
            <article class="card">
                <div class="top"><span class="tag plain">Portfolio</span><span class="tag spark">Coming soon</span></div>
                <h4>Education &amp; experience</h4>
                <p>Manage your academic and professional history.</p>
                <div class="bottom"><span>rabsrabi.com</span></div>
            </article>
            <article class="card">
                <div class="top"><span class="tag plain">Portfolio</span><span class="tag spark">Coming soon</span></div>
                <h4>Certifications</h4>
                <p>Manage your certificates and achievements.</p>
                <div class="bottom"><span>rabsrabi.com</span></div>
            </article>
            <article class="card">
                <div class="top"><span class="tag plain">System</span><span class="tag spark">Coming soon</span></div>
                <h4>System settings</h4>
                <p>Central administration settings.</p>
                <div class="bottom"><span>auth.rabsrabi.com</span></div>
            </article>
        </section>
    </main>
    <script>
    if (window.RabsBrand) {
        RabsBrand.palette.setItems([
            { group: 'Admin', label: 'Dashboard', hint: '/', href: '/' },
            { group: 'Admin', label: 'Notes editor', hint: 'blog.rabsrabi.com', href: 'https://blog.rabsrabi.com/admin/' },
            { group: 'Admin', label: 'Sign out', hint: '', href: '?route=logout' }
        ]);
    }
    </script>
<?php
    render_footer(true);
    exit;
}

// ---------------------------------------------------------------------------
// Signed out: sign-in page
// ---------------------------------------------------------------------------

render_message(
    'Sign in',
    'rabsrabi admin',
    'One central place to manage your digital platforms.',
    '/login',
    'Continue with GitHub',
    'Sign in with your authorized GitHub account to continue.'
);
