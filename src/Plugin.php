<?php

namespace workosauth;

use Craft;
use craft\base\Model;
use craft\base\Plugin as BasePlugin;
use craft\controllers\UsersController;
use craft\events\RegisterUrlRulesEvent;
use craft\events\TemplateEvent;
use craft\web\UrlManager;
use craft\web\User;
use craft\web\View;
use yii\base\ActionEvent;
use yii\base\Controller;
use yii\base\Event;
use yii\web\UserEvent;
use workosauth\models\Settings;
use workosauth\services\WorkOSService;

/**
 * WorkOS Auth Plugin for Craft CMS
 *
 * Provides WorkOS AuthKit and SSO integration for Control Panel authentication.
 *
 * @property WorkOSService $workos
 * @property Settings $settings
 * @method Settings getSettings()
 */
class Plugin extends BasePlugin
{
    /**
     * @var Plugin
     */
    public static Plugin $plugin;

    /**
     * @var string
     */
    public string $schemaVersion = '1.0.0';

    /**
     * @var bool
     */
    public bool $hasCpSettings = true;

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        parent::init();
        self::$plugin = $this;

        // Register components
        $this->setComponents([
            'workos' => WorkOSService::class,
        ]);

        // Defer setup tasks until Craft is fully initialized
        Craft::$app->onInit(function () {
            $this->attachEventHandlers();
        });

        Craft::info('WorkOS Auth plugin loaded', __METHOD__);
    }

    /**
     * Returns the WorkOS service instance
     */
    public function getWorkos(): WorkOSService
    {
        return $this->get('workos');
    }

    /**
     * @inheritdoc
     */
    protected function createSettingsModel(): ?Model
    {
        return new Settings();
    }

    /**
     * @inheritdoc
     */
    protected function settingsHtml(): ?string
    {
        return Craft::$app->getView()->renderTemplate(
            'workos-auth/settings',
            ['settings' => $this->getSettings()]
        );
    }

    /**
     * Attach event handlers
     */
    private function attachEventHandlers(): void
    {
        // Register CP URL rules for the auth controller
        Event::on(
            UrlManager::class,
            UrlManager::EVENT_REGISTER_CP_URL_RULES,
            function (RegisterUrlRulesEvent $event) {
                $event->rules['workos-auth/login'] = 'workos-auth/auth/login';
                $event->rules['workos-auth/callback'] = 'workos-auth/auth/callback';
                $event->rules['workos-auth/logout'] = 'workos-auth/auth/logout';
            }
        );

        // Register site URL rules for callback, login and webhook
        Event::on(
            UrlManager::class,
            UrlManager::EVENT_REGISTER_SITE_URL_RULES,
            function (RegisterUrlRulesEvent $event) {
                $event->rules['workos-auth/login'] = 'workos-auth/auth/login';
                $event->rules['workos-auth/callback'] = 'workos-auth/auth/callback';
                $event->rules['workos-auth/webhook'] = 'workos-auth/webhook/handle';
            }
        );

        // Hook into the login page
        if (!Craft::$app->request->isConsoleRequest) {
            $this->registerLoginHook();
            $this->registerLogoutHook();
        }
    }

    /**
     * Register hook to modify the CP login page
     */
    private function registerLoginHook(): void
    {
        // Hook into UsersController to intercept login action
        Event::on(
            UsersController::class,
            Controller::EVENT_BEFORE_ACTION,
            function (ActionEvent $event) {
                if ($event->action->id !== 'login') {
                    return;
                }

                $settings = $this->getSettings();

                if (!$settings->enabled || !$settings->replaceDefaultLogin) {
                    return;
                }

                if (!$this->getWorkos()->isConfigured()) {
                    Craft::warning("WorkOS: Cannot replace login - WorkOS not configured", __METHOD__);
                    return;
                }

                if (!Craft::$app->getUser()->getIsGuest()) {
                    return;
                }

                // Don't auto-redirect if user just logged out or had an error
                if (isset($_COOKIE['workos_just_logged_out'])) {
                    setcookie('workos_just_logged_out', '', time() - 3600, '/');
                    Craft::info("WorkOS: User just logged out, showing login page", __METHOD__);
                    return;
                }
                
                if (isset($_COOKIE['workos_login_bypass'])) {
                    setcookie('workos_login_bypass', '', time() - 3600, '/');
                    Craft::info("WorkOS: Bypass cookie found, showing login page with error", __METHOD__);
                    return;
                }

                Craft::info("WorkOS: Intercepting login action, redirecting to WorkOS", __METHOD__);
                $event->isValid = false;
                $this->redirectToWorkOSLogin();
            }
        );

        // Inject WorkOS login button into the login page via JavaScript
        Event::on(
            View::class,
            View::EVENT_AFTER_RENDER_PAGE_TEMPLATE,
            function (TemplateEvent $event) {
                $template = $event->template;
                $isLoginPage = ($template === 'login.twig' || $template === 'login' ||
                    str_ends_with($template, '/login.twig') || str_ends_with($template, '/login'));

                if (!$isLoginPage) {
                    return;
                }

                $settings = $this->getSettings();

                if (!$settings->enabled) {
                    return;
                }

                $loginUrl = '/workos-auth/login';
                $buttonText = $settings->loginButtonText ?: 'Sign in with SSO';
                $replaceDefault = $settings->replaceDefaultLogin;

                $js = $this->getLoginButtonScript($loginUrl, $buttonText, $replaceDefault);
                $event->output = str_replace('</body>', $js . '</body>', $event->output);

                Craft::info("WorkOS: Button script injected", __METHOD__);
            }
        );
    }

    /**
     * Register hook for logout
     */
    private function registerLogoutHook(): void
    {
        Event::on(
            User::class,
            User::EVENT_BEFORE_LOGOUT,
            function (UserEvent $event) {
                $settings = $this->getSettings();
                if ($settings->replaceDefaultLogin) {
                    // Use raw setcookie for consistency with bypass cookie
                    setcookie('workos_just_logged_out', '1', [
                        'expires' => time() + 60,
                        'path' => '/',
                        'secure' => Craft::$app->getRequest()->getIsSecureConnection(),
                        'httponly' => true,
                        'samesite' => 'Lax',
                    ]);
                }
            }
        );
    }

    /**
     * Redirect to WorkOS login
     */
    private function redirectToWorkOSLogin(): void
    {
        $settings = $this->getSettings();

        // Get the return URL but filter out callback URLs to prevent loops
        $returnUrl = Craft::$app->getUser()->getReturnUrl();
        if ($returnUrl && str_contains($returnUrl, 'workos-auth/callback')) {
            $cpTrigger = Craft::$app->getConfig()->getGeneral()->cpTrigger;
            $returnUrl = '/' . $cpTrigger;
        }
        Craft::$app->getSession()->set('workos_return_url', $returnUrl);

        $loginUrl = $this->getWorkos()->getAuthorizationUrl(
            null,
            $settings->connectionId ?: null,
            $settings->organizationId ?: null,
            $settings->provider ?: null
        );

        Craft::$app->getResponse()->redirect($loginUrl);
        Craft::$app->end();
    }

    /**
     * Get JavaScript to inject the WorkOS login button
     */
    private function getLoginButtonScript(string $loginUrl, string $buttonText, bool $replaceDefault = false): string
    {
        $replaceDefaultJs = $replaceDefault ? 'true' : 'false';

        return <<<HTML
<script>
(function() {
    var replaceDefault = {$replaceDefaultJs};

    function getCookie(name) {
        var value = "; " + document.cookie;
        var parts = value.split("; " + name + "=");
        if (parts.length === 2) return decodeURIComponent(parts.pop().split(";").shift());
        return null;
    }

    function deleteCookie(name) {
        document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    }

    var errorMessage = getCookie('workos_auth_error');
    if (errorMessage) {
        deleteCookie('workos_auth_error');
    }

    function addWorkOSButton() {
        var form = document.getElementById('login-form');
        var loginContainer = document.getElementById('login');

        if (!form || !loginContainer) {
            setTimeout(addWorkOSButton, 100);
            return;
        }

        if (document.getElementById('workos-login-btn')) {
            return;
        }

        if (errorMessage) {
            var errorDiv = document.createElement('div');
            errorDiv.id = 'workos-error';
            errorDiv.style.cssText = 'background: #fee2e2; border: 1px solid #fecaca; color: #dc2626; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; font-size: 14px;';
            errorDiv.textContent = errorMessage;

            var h1 = loginContainer.querySelector('h1');
            if (h1) {
                h1.parentNode.insertBefore(errorDiv, h1.nextSibling);
            } else {
                loginContainer.insertBefore(errorDiv, loginContainer.firstChild);
            }
        }

        var btnContainer = document.createElement('div');
        btnContainer.id = 'workos-login-btn';

        var btn = document.createElement('a');
        btn.href = '{$loginUrl}';
        btn.className = 'btn submit fullwidth';
        btn.style.cssText = 'display: flex; align-items: center; justify-content: center; gap: 8px; background: #6366f1; border-color: #6366f1; color: white;';
        btn.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink: 0;"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" fill="currentColor"/></svg><span>{$buttonText}</span>';

        btnContainer.appendChild(btn);

        if (replaceDefault) {
            form.style.display = 'none';
            var extras = document.getElementById('login-form-extra');
            if (extras) extras.style.display = 'none';
            var errors = document.getElementById('login-errors');
            if (errors) errors.style.display = 'none';
            btnContainer.style.cssText = 'margin-top: 24px;';
            form.parentNode.insertBefore(btnContainer, form);
        } else {
            var separator = document.createElement('div');
            separator.style.cssText = 'margin: 24px 0; text-align: center; position: relative;';
            separator.innerHTML = '<span style="background: var(--gray-050, #f8f8f8); padding: 0 12px; position: relative; z-index: 1; color: var(--gray-400, #9aa5b1); font-size: 12px;">or</span><hr style="position: absolute; top: 50%; left: 0; right: 0; border: none; border-top: 1px solid var(--gray-200, #e2e8f0); margin: 0;">';
            btnContainer.style.cssText = 'margin-top: 24px;';
            form.parentNode.insertBefore(separator, form.nextSibling);
            form.parentNode.insertBefore(btnContainer, separator.nextSibling);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', addWorkOSButton);
    } else {
        addWorkOSButton();
    }
})();
</script>
HTML;
    }

    /**
     * Check if a domain is allowed for login
     */
    public function isAllowedDomain(string $email): bool
    {
        $settings = $this->getSettings();
        $allowedDomains = $settings->getAllowedDomainsArray();

        if (empty($allowedDomains)) {
            return true;
        }

        $emailDomain = substr(strrchr($email, '@'), 1);
        return in_array($emailDomain, $allowedDomains, true);
    }

    /**
     * Check if an email domain should get admin access
     */
    public function isAdminDomain(string $email): bool
    {
        $settings = $this->getSettings();
        $adminDomains = $settings->getAdminEmailDomainsArray();

        if (empty($adminDomains)) {
            return false;
        }

        $emailDomain = substr(strrchr($email, '@'), 1);
        return in_array($emailDomain, $adminDomains, true);
    }
}
