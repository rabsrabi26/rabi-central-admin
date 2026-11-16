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

        <style>
            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f4f6fa;
                color: #202938;
            }

            header {
                background: #172033;
                color: white;
                padding: 22px 35px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            header h1 {
                margin: 0;
                font-size: 22px;
            }

            header a {
                color: white;
                text-decoration: none;
            }

            main {
                max-width: 1100px;
                margin: 45px auto;
                padding: 0 22px;
            }

            .welcome {
                margin-bottom: 35px;
            }

            .welcome h2 {
                margin-bottom: 8px;
            }

            .grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
                gap: 20px;
            }

            .card {
                background: white;
                padding: 25px;
                border-radius: 12px;
                border: 1px solid #e5e7eb;
            }

            .card h3 {
                margin-top: 0;
            }

            .card p {
                color: #64748b;
                line-height: 1.5;
            }

            .status {
                color: #16803c;
                font-weight: bold;
            }
        </style>
    </head>

    <body>

        <header>
            <h1>Rabi Central Admin</h1>
            <a href="?route=logout">Sign out</a>
        </header>

        <main>

            <section class="welcome">
                <h2>Welcome, <?= $name ?></h2>
                <p>Signed in as <?= $login ?></p>
                <p class="status">● Authentication successful</p>
            </section>

            <section class="grid">

                <div class="card">
                    <h3>Portfolio Management</h3>
                    <p>Manage your personal portfolio website.</p>
                    <p>Coming soon</p>
                </div>

                <div class="card">
                    <h3>Blog Management</h3>
                    <p>Manage your RabiNotes blog content.</p>
                    <p>Coming soon</p>
                </div>

                <div class="card">
                    <h3>Projects & Research</h3>
                    <p>Manage projects, publications and research.</p>
                    <p>Coming soon</p>
                </div>

                <div class="card">
                    <h3>Education & Experience</h3>
                    <p>Manage your academic and professional history.</p>
                    <p>Coming soon</p>
                </div>

                <div class="card">
                    <h3>Certifications</h3>
                    <p>Manage your certificates and achievements.</p>
                    <p>Coming soon</p>
                </div>

                <div class="card">
                    <h3>System Settings</h3>
                    <p>Central administration settings.</p>
                    <p>Coming soon</p>
                </div>

            </section>

        </main>

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
</head>
<body>
    <h1>Rabi Central Admin</h1>
    <p>Sign in with your authorized GitHub account.</p>
    <a href="/login">Continue with GitHub</a>
</body>
</html>