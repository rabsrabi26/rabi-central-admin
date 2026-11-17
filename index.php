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
        echo 'GitHub authentication failed. Please check the server error log.';
        exit;
    }
}



if (!empty($_SESSION['authenticated'])) {

    $name = htmlspecialchars(
        $_SESSION['github_name'] ?? 'Administrator',
        ENT_QUOTES,
        'UTF-8'
    );

    $login = htmlspecialchars(
        $_SESSION['github_login'] ?? '',
        ENT_QUOTES,
        'UTF-8'
    );

    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Rabi Central Admin</title>
        <link rel="stylesheet" href="/admin.css">
    </head>
    <body>
<header class="admin-header">
    <div class="admin-container admin-topbar">
        <div class="admin-brand">RABI / CENTRAL ADMIN</div>

        <div class="admin-topbar-actions">
            <div class="admin-theme" role="group" aria-label="Theme selection">
                <button type="button" data-theme-choice="system" aria-pressed="true">System</button>
                <button type="button" data-theme-choice="light" aria-pressed="false">Light</button>
                <button type="button" data-theme-choice="dark" aria-pressed="false">Dark</button>
            </div>
            <a href="?route=logout">Sign out</a>
        </div>
    </div>
</header>
    <main class="admin-main">
        <div class="admin-container">
            <section class="admin-panel admin-dashboard">
                <h1>Welcome, <?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?></h1>
                <p>Signed in as <?= htmlspecialchars($login, ENT_QUOTES, 'UTF-8') ?></p>
                <p class="admin-status">● Authentication successful</p>
            </section>

            <section class="admin-grid">
                <div class="admin-card">
                    <h2>Portfolio Management</h2>
                    <p>Manage your personal portfolio website.</p>
                    <span class="admin-status">Coming soon</span>
                </div>

                <div class="admin-card">
                    <h2>Blog Management</h2>
                    <p>Manage your RabiNotes blog content.</p>
                    <span class="admin-status">Coming soon</span>
                </div>

                <div class="admin-card">
                    <h2>Projects &amp; Research</h2>
                    <p>Manage projects, publications and research.</p>
                    <span class="admin-status">Coming soon</span>
                </div>

                <div class="admin-card">
                    <h2>Education &amp; Experience</h2>
                    <p>Manage your academic and professional history.</p>
                    <span class="admin-status">Coming soon</span>
                </div>

                <div class="admin-card">
                    <h2>Certifications</h2>
                    <p>Manage your certificates and achievements.</p>
                    <span class="admin-status">Coming soon</span>
                </div>

                <div class="admin-card">
                    <h2>System Settings</h2>
                    <p>Central administration settings.</p>
                    <span class="admin-status">Coming soon</span>
                </div>
            </section>
        </div>
    </main>

<script>
(function () {
    const root = document.documentElement;
    const buttons = document.querySelectorAll('[data-theme-choice]');
    const storageKey = 'rabi-admin-theme';

    function getPreference() {
        try {
            return localStorage.getItem(storageKey) || 'system';
        } catch (error) {
            return 'system';
        }
    }

    function applyTheme(preference) {
        const valid = ['system', 'light', 'dark'];
        if (!valid.includes(preference)) preference = 'system';

        if (preference === 'system') {
            root.removeAttribute('data-theme');
        } else {
            root.setAttribute('data-theme', preference);
        }

        buttons.forEach(function (button) {
            button.setAttribute(
                'aria-pressed',
                String(button.dataset.themeChoice === preference)
            );
        });
    }

    buttons.forEach(function (button) {
        button.addEventListener('click', function () {
            const preference = button.dataset.themeChoice;

            try {
                localStorage.setItem(storageKey, preference);
            } catch (error) {
                // Theme still works for this page if storage is unavailable.
            }

            applyTheme(preference);
        });
    });

    applyTheme(getPreference());

    const systemPreference = window.matchMedia('(prefers-color-scheme: dark)');

    systemPreference.addEventListener('change', function () {
        if (getPreference() === 'system') {
            applyTheme('system');
        }
    });
})();
</script>
</body>
    </html>
    <?php

    exit;
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Rabi Central Admin</title>
    <link rel="stylesheet" href="/admin.css">
</head>
<body>
    <header class="admin-header">
        <div class="admin-container">
            <div class="admin-brand">RABI / CENTRAL ADMIN</div>
        </div>
    </header>

    <main class="admin-main">
        <div class="admin-container">
            <section class="admin-panel">
                <h1>Rabi Central Admin</h1>
                <p>One central place to manage your digital platforms.</p>
                <p class="admin-muted">Sign in with your authorized GitHub account to continue.</p>

                <a class="admin-button" href="/login">
                    Continue with GitHub
                </a>
            </section>
        </div>
    </main>
</body>
</html>