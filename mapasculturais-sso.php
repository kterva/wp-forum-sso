<?php
/**
 * Plugin Name: Mapas Culturais Foro SSO
 * Plugin URI: https://github.com/LibreCoopUruguay
 * Description: Sistema de Single Sign-On (SSO) que conecta WordPress con Mapas Culturais, permitiendo el acceso exclusivamente a usuarios con el Sello "Puntos de Cultura" (PDC).
 * Version: 1.0.0
 * Author: LibreCoop
 * License: GPL-2.0+
 */

// Evitar acceso directo
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class MapasCulturais_SSO {

    // ==== CONFIGURACIÓN ====
    private $mapas_url_client;
    private $mapas_url_server;
    private $shared_secret;
    private $required_seal_id;

    public function __construct() {
        // Cargar ajustes desde la base de datos de WordPress
        $this->mapas_url_client = get_option('mc_sso_client_url', 'http://localhost:8081');
        $this->mapas_url_server = get_option('mc_sso_server_url', 'http://mapas:80');
        $this->required_seal_id = get_option('mc_sso_seal_id', 2);
        
        // Obtener el secreto compartido de DB, entorno o constante WP
        $db_secret = get_option('mc_sso_shared_secret', '');
        $this->shared_secret = defined('MAPAS_SSO_SECRET') ? MAPAS_SSO_SECRET : (getenv('MAPAS_SSO_SECRET') ?: ($db_secret ?: 'fallback_dev_secret_12345'));

        // Redirigir la página de login de WP a Mapas Culturais
        add_action('login_init', array($this, 'redirect_to_mapas_login'));
        
        // Interceptar el retorno desde Mapas Culturais
        add_action('init', array($this, 'handle_mapas_callback'));

        // Single Log-Out (SLO): Si sale del foro, que salga del Mapa también y no se autologuee
        add_action('wp_logout', array($this, 'redirect_after_logout'));

        // Mostrar página de rechazo personalizada (en vez del login gris)
        add_action('template_redirect', array($this, 'render_sso_denied_page'));

        // Registrar panel de administración
        add_action('admin_menu', array($this, 'add_plugin_page'));
        add_action('admin_init', array($this, 'page_init'));
    }

    public function add_plugin_page() {
        add_options_page('Configuración SSO Mapas Culturais', 'Mapas SSO', 'manage_options', 'mapas-sso-setting-admin', array($this, 'create_admin_page'));
    }

    public function create_admin_page() {
        ?>
        <div class="wrap">
            <h1>Configuración de Mapas Culturais SSO</h1>
            <p>Ajuste las URLs del proveedor de identidad (Mapas Culturais) y el sello requerido.</p>
            <form method="post" action="options.php">
            <?php
                settings_fields('mc_sso_option_group');
                do_settings_sections('mapas-sso-setting-admin');
                submit_button();
            ?>
            </form>
        </div>
        <?php
    }

    public function page_init() {
        register_setting('mc_sso_option_group', 'mc_sso_client_url');
        register_setting('mc_sso_option_group', 'mc_sso_server_url');
        register_setting('mc_sso_option_group', 'mc_sso_seal_id');
        register_setting('mc_sso_option_group', 'mc_sso_shared_secret');

        add_settings_section('mc_sso_setting_section', 'Ajustes de Conexión y Filtro', null, 'mapas-sso-setting-admin');

        add_settings_field('mc_sso_client_url', 'URL Pública de Mapas Culturais', array($this, 'client_url_callback'), 'mapas-sso-setting-admin', 'mc_sso_setting_section');
        add_settings_field('mc_sso_server_url', 'URL Interna para Auth API', array($this, 'server_url_callback'), 'mapas-sso-setting-admin', 'mc_sso_setting_section');
        add_settings_field('mc_sso_seal_id', 'ID del Sello Requerido', array($this, 'seal_id_callback'), 'mapas-sso-setting-admin', 'mc_sso_setting_section');
        add_settings_field('mc_sso_shared_secret', 'Secreto Compartido', array($this, 'shared_secret_callback'), 'mapas-sso-setting-admin', 'mc_sso_setting_section');
    }

    public function client_url_callback() {
        printf('<input type="url" id="mc_sso_client_url" name="mc_sso_client_url" value="%s" class="regular-text" />', esc_attr($this->mapas_url_client));
        echo '<p class="description">La URL que el usuario ve en su navegador para ir a loguearse (ej: https://culturaenlinea.uy).</p>';
    }

    public function server_url_callback() {
        printf('<input type="url" id="mc_sso_server_url" name="mc_sso_server_url" value="%s" class="regular-text" />', esc_attr($this->mapas_url_server));
        echo '<p class="description">Si Mapas Culturais y WordPress comparten la misma red Docker, usa la URL interna (ej: http://mapas:80). Si están totalmente separados por Internet, repite la URL pública de arriba.</p>';
    }

    public function seal_id_callback() {
        printf('<input type="number" id="mc_sso_seal_id" name="mc_sso_seal_id" value="%s" />', esc_attr($this->required_seal_id));
        echo '<p class="description">Sólo los perfiles de agentes que posean este ID de sello numérico en Mapas Culturais tendrán acceso a iniciar sesión en WordPress.</p>';
    }

    public function shared_secret_callback() {
        $secret = get_option('mc_sso_shared_secret', '');
        printf('<input type="password" id="mc_sso_shared_secret" name="mc_sso_shared_secret" value="%s" class="regular-text" />', esc_attr($secret));
        echo '<p class="description">Clave que autoriza la comunicación Server-to-Server. Debe coincidir exactamente con el <code>wp_sso.secret</code> de Mapas Culturais.</p>';
    }

    /**
     * Paso 0: Single Log-Out (SLO) a nivel de servidor IDP (Mapas)
     */
    public function redirect_after_logout() {
        // Redirigir al endpoint nativo de cierre de sesión de Mapas Culturais (en portugués)
        $logout_url = $this->mapas_url_client . '/sair';
        wp_redirect($logout_url);
        exit;
    }

    /**
     * Paso 1: Usuario intenta entrar a wp-login.php, lo mandamos a Mapas Culturais
     */
    public function redirect_to_mapas_login() {
        // Protegemos para no crear bucles si ya viene de retorno
        if (isset($_GET['mc_token']) || isset($_GET['sso_error'])) {
            return;
        }

        // Si intentan cerrar sesión, dejar que WP lo haga
        if (isset($_GET['action']) && $_GET['action'] == 'logout') {
            return;
        }

        // Si acaban de desconectarse, evitamos un auto-login silencioso y mostramos el form
        if (isset($_GET['loggedout']) && $_GET['loggedout'] == 'true') {
            return;
        }

        // Si se está enviando el formulario local de WP (POST data exist), permitimos el proceso nativo
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['log']) && isset($_POST['pwd'])) {
            return;
        }

        // Puerta trasera para administradores locales de WP: wp-login.php?native=1
        if (isset($_GET['native']) && $_GET['native'] == '1') {
            return;
        }

        // A dónde debe volver el usuario después del login
        $redirect_to = isset($_GET['redirect_to']) ? $_GET['redirect_to'] : home_url();

        // Parámetro de seguridad State (CSRF Protection)
        $state = wp_generate_password(24, false);
        set_transient('mapas_sso_state_' . $state, 'valid', 5 * MINUTE_IN_SECONDS);

        // Armar URL del IdP (Mapas)
        $auth_url = $this->mapas_url_client . '/wp-sso/login' . 
                    '?redirect_to=' . urlencode(wp_login_url()) . 
                    '&state=' . urlencode($state);

        wp_redirect($auth_url);
        exit;
    }

    /**
     * Página visual de aterrizaje para rechazos (independiente del login)
     */
    public function render_sso_denied_page() {
        if (isset($_GET['sso_denied'])) {
            $reason = sanitize_text_field($_GET['sso_denied']);
            
            $blog_url = home_url();
            $mapas_url = $this->mapas_url_client;
            
            $title = 'Acceso Restringido';
            $message = '';
            
            if ($reason == 'seal') {
                $message = '<p>Lo sentimos, el acceso a este foro de debate es <strong>exclusivo para integrantes verificados</strong>.</p>
                            <p>Hemos verificado tu identidad, pero tu perfil actual no posee el Sello requerido (<b>Puntos de Cultura</b>). Para participar, comunícate con la administración para solicitar que configuren este sello en tu perfil de agente.</p>';
            } else if ($reason == 'api') {
                $message = '<p>Se produjo un error de seguridad o conexión con Cultura en Línea durante la validación de tu identidad. Inténtalo más tarde.</p>';
            } else {
                $message = '<p>Sesión caducada o inválida. Seguridad de token comprometida.</p>';
            }
            
            echo '<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acceso Restringido - Foro Cultural</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #1f2937; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
        .container { background: white; padding: 48px 40px; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.1), 0 8px 10px -6px rgba(0,0,0,0.1); max-width: 540px; text-align: center; border-top: 6px solid #ef4444; }
        .icon { font-size: 64px; display: block; margin-bottom: 20px; text-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        h1 { margin-top: 0; color: #111827; font-size: 26px; font-weight: 800; letter-spacing: -0.025em; }
        p { line-height: 1.6; color: #4b5563; font-size: 16px; margin-bottom: 20px; }
        .buttons { display: flex; gap: 15px; justify-content: center; margin-top: 36px; flex-wrap: wrap; }
        .btn { padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px; transition: all 0.2s; white-space: nowrap; }
        .btn-primary { background: #4f46e5; color: white; border: 1px solid #4f46e5; box-shadow: 0 4px 6px rgba(79, 70, 229, 0.2); }
        .btn-primary:hover { background: #4338ca; border-color: #4338ca; transform: translateY(-1px); }
        .btn-outline { background: white; color: #4b5563; border: 1px solid #d1d5db; }
        .btn-outline:hover { background: #f3f4f6; color: #111827; transform: translateY(-1px); }
    </style>
</head>
<body>
    <div class="container">
        <span class="icon">✋</span>
        <h1>' . $title . '</h1>
        ' . $message . '
        <div class="buttons">
            <a href="' . $mapas_url . '" class="btn btn-primary">⬅ Ir a Cultura en Línea</a>
            <a href="' . $blog_url . '" class="btn btn-outline">Volver al Foro</a>
        </div>
    </div>
</body>
</html>';
            exit;
        }
    }

    /**
     * Paso 2 y 3: Mapas devolvió al usuario con un Token. Hay que verificarlo en Backend.
     */
    public function handle_mapas_callback() {
        if (!isset($_GET['mc_token']) || !isset($_GET['state'])) {
            return;
        }

        $token = sanitize_text_field($_GET['mc_token']);
        $state = sanitize_text_field($_GET['state']);

        // 1. Verificar State (CSRF)
        if (get_transient('mapas_sso_state_' . $state) !== 'valid') {
            wp_redirect(home_url('/?sso_denied=session'));
            exit;
        }
        delete_transient('mapas_sso_state_' . $state);

        // 2. Consulta Server-to-Server a Mapas Culturais
        $verify_endpoint = $this->mapas_url_server . '/wp-sso/verify';
        $response = wp_remote_post($verify_endpoint, array(
            'body' => array(
                'token' => $token,
                'secret' => $this->shared_secret
            ),
            'timeout' => 15
        ));

        if (is_wp_error($response)) {
            wp_redirect(home_url('/?sso_denied=api'));
            exit;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!$data || (isset($data['error']) && $data['error'] == true)) {
            wp_redirect(home_url('/?sso_denied=api'));
            exit;
        }

        // 3. LA REGLA DEL SELLO (El "Filtro")
        $tiene_sello = false;
        
        if (isset($data['agent']['seals']) && is_array($data['agent']['seals'])) {
            if (in_array($this->required_seal_id, $data['agent']['seals'])) {
                $tiene_sello = true;
            }
        }

        if (!$tiene_sello) {
            wp_redirect(home_url('/?sso_denied=seal'));
            exit;
        }

        // 4. Iniciar Sesión en WordPress
        $this->login_or_create_wp_user($data);
    }

    /**
     * Paso 4: Mapear el usuario de Mapas a WordPress y forzar el logueo
     */
    private function login_or_create_wp_user($mapas_data) {
        $email = sanitize_email($mapas_data['user']['email']);
        $username = 'mc_' . intval($mapas_data['user']['id']);
        
        // Primero buscar por ID de mapa (login local de WP)
        $user = get_user_by('login', $username);

        // Si no existe, intentar por correo por seguridad
        if (!$user) {
            $user = get_user_by('email', $email);
        }

        if (!$user) {
            // Si el usuario no existe en WP, lo creamos
            $random_password = wp_generate_password(12, false);
            $user_id = wp_create_user($username, $random_password, $email);
            
            if (is_wp_error($user_id)) {
                $error_msg = $user_id->get_error_message();
                wp_die('Error fatal creando cuenta local en el foro (Usuario: ' . esc_html($username) . ' | Email: ' . esc_html($email) . '). Mensaje técnico: ' . esc_html($error_msg));
            }

            // Actualizar nombre visible
            wp_update_user(array(
                'ID' => $user_id,
                'display_name' => sanitize_text_field($mapas_data['agent']['name'])
            ));

            $user = get_user_by('id', $user_id);
        }

        // Forzar Autenticación
        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);

        // ¡Logueado! Redirigir al Foro
        wp_redirect(home_url('/'));
        exit;
    }
}

// Iniciar Plugin
new MapasCulturais_SSO();
