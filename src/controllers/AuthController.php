<?php

namespace workosauth\controllers;

use Craft;
use craft\elements\User;
use craft\web\Controller;
use workosauth\Plugin;
use yii\web\Response;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;

/**
 * Auth Controller
 *
 * Handles WorkOS authentication flow including login redirect,
 * OAuth callback processing, and user session management.
 */
class AuthController extends Controller
{
    /**
     * @inheritdoc
     */
    protected array|bool|int $allowAnonymous = ['login', 'callback'];

    /**
     * @inheritdoc
     */
    public $enableCsrfValidation = false;

    /**
     * Initiate WorkOS login flow
     */
    public function actionLogin(): Response
    {
        $plugin = Plugin::getInstance();
        $workos = $plugin->getWorkos();
        $settings = $plugin->getSettings();

        if (!$workos->isConfigured()) {
            return $this->redirectToLoginWithError('WorkOS is not configured. Please contact the administrator.');
        }

        $request = Craft::$app->getRequest();
        $connectionId = $request->getQueryParam('connection') ?? $settings->connectionId ?? null;
        $organizationId = $request->getQueryParam('organization') ?? $settings->organizationId ?? null;
        $provider = $request->getQueryParam('provider') ?? $settings->provider ?? null;

        $returnUrl = $request->getQueryParam('redirect') ?? Craft::$app->getUser()->getReturnUrl();
        $returnUrl = $this->validateReturnUrl($returnUrl);
        // Filter out callback URLs to prevent loops
        if ($returnUrl && str_contains($returnUrl, 'workos-auth/callback')) {
            $cpTrigger = Craft::$app->getConfig()->getGeneral()->cpTrigger;
            $returnUrl = '/' . $cpTrigger;
        }
        Craft::$app->getSession()->set('workos_return_url', $returnUrl);

        try {
            $authUrl = $workos->getAuthorizationUrl(
                null,
                $connectionId ?: null,
                $organizationId ?: null,
                $provider ?: null
            );

            return $this->redirect($authUrl);
        } catch (\Exception $e) {
            Craft::error('Failed to generate WorkOS authorization URL: ' . $e->getMessage(), __METHOD__);
            return $this->redirectToLoginWithError('Unable to connect to authentication service. Please try again.');
        }
    }

    /**
     * Handle OAuth callback from WorkOS
     */
    public function actionCallback(): Response
    {
        $request = Craft::$app->getRequest();
        $plugin = Plugin::getInstance();
        $workos = $plugin->getWorkos();

        $error = $request->getQueryParam('error');
        if ($error) {
            $errorDescription = $request->getQueryParam('error_description', 'Authentication failed');
            $errorDescription = strip_tags($errorDescription);
            $errorDescription = mb_substr($errorDescription, 0, 200);
            Craft::error("WorkOS authentication error: {$error} - {$errorDescription}", __METHOD__);
            return $this->redirectToLoginWithError($errorDescription);
        }

        $code = $request->getQueryParam('code');
        if (!$code) {
            throw new BadRequestHttpException('Authorization code is required.');
        }

        $state = $request->getQueryParam('state');
        $storedState = Craft::$app->getSession()->get('workos_oauth_state');
        Craft::$app->getSession()->remove('workos_oauth_state');

        $normalizedState = trim($state ?? '', '"');
        $stateValid = $storedState && $normalizedState === $storedState;

        if (!$stateValid) {
            return $this->redirectToLoginWithError('Authentication failed. Please try again.');
        }

        try {
            $workosUser = $workos->authenticateWithCode($code);
            $craftUser = $this->processWorkOSUser($workosUser);

            if (!$craftUser) {
                return $this->redirectToLoginWithError('Unable to create or find user account.');
            }

            $loginResult = $this->loginUser($craftUser);
            if (!$loginResult['success']) {
                return $this->redirectToLoginWithError($loginResult['error']);
            }

            $returnUrl = Craft::$app->getSession()->get('workos_return_url');
            Craft::$app->getSession()->remove('workos_return_url');

            if (!$returnUrl || $returnUrl === '/' || $returnUrl === Craft::$app->getSites()->getCurrentSite()->getBaseUrl()) {
                $cpTrigger = Craft::$app->getConfig()->getGeneral()->cpTrigger;
                $returnUrl = '/' . $cpTrigger;
            }

            return $this->redirect($returnUrl);

        } catch (ForbiddenHttpException $e) {
            return $this->redirectToLoginWithError($e->getMessage());

        } catch (\Exception $e) {
            Craft::error('WorkOS authentication failed: ' . $e->getMessage(), __METHOD__);
            return $this->redirectToLoginWithError('Authentication failed. Please try again.');
        }
    }

    /**
     * Logout action
     */
    public function actionLogout(): Response
    {
        Craft::$app->getUser()->logout();
        $this->setBypassAutoRedirectCookie();
        return $this->redirect(Craft::$app->getConfig()->getGeneral()->getLoginPath());
    }

    /**
     * Set a cookie to bypass auto-redirect to WorkOS on the login page
     */
    private function setBypassAutoRedirectCookie(): void
    {
        // Use raw setcookie for consistency - Craft's cookie system encrypts values
        setcookie('workos_login_bypass', '1', [
            'expires' => time() + 300,
            'path' => '/',
            'secure' => Craft::$app->getRequest()->getIsSecureConnection(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * Redirect to login page with error
     */
    private function redirectToLoginWithError(string $errorMessage): Response
    {
        $this->setBypassAutoRedirectCookie();

        $displayMessage = $this->getDisplayError($errorMessage);

        $secure = Craft::$app->getRequest()->getIsSecureConnection();
        setcookie('workos_auth_error', $displayMessage, [
            'expires' => time() + 60,
            'path' => '/',
            'secure' => $secure,
            'httponly' => false,
            'samesite' => 'Lax',
        ]);

        Craft::warning("WorkOS auth error: {$errorMessage}", __METHOD__);

        return $this->redirect(Craft::$app->getConfig()->getGeneral()->getLoginPath());
    }

    /**
     * Get the error message to display based on debug mode
     */
    private function getDisplayError(string $detailedMessage): string
    {
        $settings = Plugin::getInstance()->getSettings();

        if ($settings->debug) {
            return $detailedMessage;
        }

        return 'Authentication failed. Please try again or contact your administrator.';
    }

    /**
     * Validate return URL to prevent open redirect attacks
     */
    private function validateReturnUrl(?string $url): ?string
    {
        if (!$url) {
            return null;
        }

        if (str_starts_with($url, '/') && !str_starts_with($url, '//')) {
            return $url;
        }

        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['host'])) {
            return null;
        }

        $currentHost = Craft::$app->getRequest()->getHostName();

        if (strcasecmp($parsed['host'], $currentHost) === 0) {
            return $url;
        }

        Craft::warning("Blocked potential open redirect to: {$url}", __METHOD__);
        return null;
    }

    /**
     * Process WorkOS user data and find/create corresponding Craft user
     */
    private function processWorkOSUser(array $workosUser): ?User
    {
        $plugin = Plugin::getInstance();
        $settings = $plugin->getSettings();
        $email = $workosUser['email'] ?? null;

        if (!$email) {
            Craft::error('WorkOS user data missing email address', __METHOD__);
            return null;
        }

        if (!$plugin->isAllowedDomain($email)) {
            Craft::warning("Login attempt from unauthorized domain: {$email}", __METHOD__);
            throw new ForbiddenHttpException('Your email domain is not authorized to access this system.');
        }

        $user = User::find()
            ->email($email)
            ->status(null)
            ->one();

        if ($user) {
            if ($settings->updateUserOnLogin) {
                $this->updateUserFromWorkOS($user, $workosUser);
            }
            return $user;
        }

        if (!$settings->autoCreateUsers) {
            Craft::warning("Auto-create users is disabled, cannot create user for: {$email}", __METHOD__);
            return null;
        }

        return $this->createUserFromWorkOS($workosUser);
    }

    /**
     * Create a new Craft user from WorkOS data
     */
    private function createUserFromWorkOS(array $workosUser): ?User
    {
        $plugin = Plugin::getInstance();
        $settings = $plugin->getSettings();

        $user = new User();
        $user->email = $workosUser['email'];
        $user->username = $workosUser['email'];
        $user->firstName = $workosUser['firstName'] ?? '';
        $user->lastName = $workosUser['lastName'] ?? '';
        $user->newPassword = Craft::$app->getSecurity()->generateRandomString(32);

        if ($plugin->isAdminDomain($workosUser['email'])) {
            $user->admin = true;
        }

        $user->pending = false;

        if (!Craft::$app->getElements()->saveElement($user)) {
            Craft::error('Failed to create user: ' . implode(', ', $user->getErrorSummary(true)), __METHOD__);
            return null;
        }

        if ($settings->defaultUserGroup) {
            $group = Craft::$app->getUserGroups()->getGroupByHandle($settings->defaultUserGroup);
            if ($group) {
                Craft::$app->getUsers()->assignUserToGroups($user->id, [$group->id]);
            }
        }

        Craft::info("Created new user from WorkOS: {$user->email}", __METHOD__);

        return $user;
    }

    /**
     * Update an existing Craft user with WorkOS data
     */
    private function updateUserFromWorkOS(User $user, array $workosUser): void
    {
        $changed = false;

        if (!empty($workosUser['firstName']) && $user->firstName !== $workosUser['firstName']) {
            $user->firstName = $workosUser['firstName'];
            $changed = true;
        }

        if (!empty($workosUser['lastName']) && $user->lastName !== $workosUser['lastName']) {
            $user->lastName = $workosUser['lastName'];
            $changed = true;
        }

        if ($changed) {
            if (!Craft::$app->getElements()->saveElement($user)) {
                Craft::warning('Failed to update user: ' . implode(', ', $user->getErrorSummary(true)), __METHOD__);
            }
        }
    }

    /**
     * Attempt to log user into Craft
     */
    private function loginUser(User $user): array
    {
        if ($user->suspended) {
            return ['success' => false, 'error' => 'Your account has been suspended.'];
        }

        if ($user->locked) {
            return ['success' => false, 'error' => 'Your account is locked.'];
        }

        if ($user->pending) {
            $user->pending = false;
            Craft::$app->getElements()->saveElement($user);
        }

        Craft::$app->getSession()->regenerateID(true);

        $duration = Craft::$app->getConfig()->getGeneral()->userSessionDuration;
        $success = Craft::$app->getUser()->login($user, $duration);

        return ['success' => $success, 'error' => $success ? null : 'Login failed.'];
    }
}
