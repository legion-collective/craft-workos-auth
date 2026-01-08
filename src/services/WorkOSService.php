<?php

namespace workosauth\services;

use Craft;
use craft\base\Component;
use workosauth\Plugin;
use WorkOS\WorkOS;
use WorkOS\UserManagement;
use WorkOS\SSO;
use WorkOS\DirectorySync;

/**
 * WorkOS Service
 *
 * Handles all WorkOS API interactions including AuthKit authentication,
 * SSO, and User Management.
 */
class WorkOSService extends Component
{
    private ?string $clientId = null;
    private ?string $apiKey = null;
    private ?string $redirectUri = null;
    private bool $initialized = false;

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        parent::init();
        $this->initializeWorkOS();
    }

    /**
     * Initialize WorkOS SDK with credentials from settings (with env fallback)
     */
    private function initializeWorkOS(): void
    {
        $settings = Plugin::getInstance()?->getSettings();

        if ($settings) {
            $this->clientId = $settings->getClientId();
            $this->apiKey = $settings->getApiKey();
            $this->redirectUri = $settings->getRedirectUri();
        } else {
            // Fallback to env vars if plugin not fully initialized
            $this->clientId = Craft::parseEnv('$WORKOS_CLIENT_ID');
            $this->apiKey = Craft::parseEnv('$WORKOS_API_KEY');
            $this->redirectUri = Craft::parseEnv('$WORKOS_REDIRECT_URI');
        }

        if ($this->apiKey && $this->clientId) {
            WorkOS::setApiKey($this->apiKey);
            WorkOS::setClientId($this->clientId);
            $this->initialized = true;
        } else {
            Craft::warning('WorkOS credentials not configured. Set them in plugin settings or use WORKOS_CLIENT_ID and WORKOS_API_KEY env variables.', __METHOD__);
        }
    }

    /**
     * Check if WorkOS is properly configured
     */
    public function isConfigured(): bool
    {
        return $this->initialized && !empty($this->clientId) && !empty($this->apiKey);
    }

    /**
     * Generate the authorization URL for WorkOS AuthKit
     */
    public function getAuthorizationUrl(
        ?string $state = null,
        ?string $connectionId = null,
        ?string $organizationId = null,
        ?string $provider = null
    ): string {
        if (!$this->isConfigured()) {
            throw new \RuntimeException('WorkOS is not configured. Please set WORKOS_CLIENT_ID and WORKOS_API_KEY.');
        }

        if ($state === null) {
            $state = $this->generateState();
        }

        Craft::$app->getSession()->set('workos_oauth_state', $state);

        $userManagement = new UserManagement();

        return $userManagement->getAuthorizationUrl(
            $this->redirectUri,
            $state,
            $provider,
            $connectionId,
            null,
            null,
            $organizationId
        );
    }

    /**
     * Exchange authorization code for user information
     */
    public function authenticateWithCode(string $code): array
    {
        if (!$this->isConfigured()) {
            throw new \RuntimeException('WorkOS is not configured.');
        }

        $userManagement = new UserManagement();

        $response = $userManagement->authenticateWithCode(
            $this->clientId,
            $code
        );

        $user = $response->user;

        return [
            'id' => $user->id,
            'email' => $user->email,
            'firstName' => $user->firstName ?? '',
            'lastName' => $user->lastName ?? '',
            'emailVerified' => $user->emailVerified ?? false,
            'profilePictureUrl' => $user->profilePictureUrl ?? null,
            'createdAt' => $user->createdAt ?? null,
            'updatedAt' => $user->updatedAt ?? null,
            'accessToken' => $response->accessToken ?? null,
            'refreshToken' => $response->refreshToken ?? null,
            'organizationId' => $response->organizationId ?? null,
        ];
    }

    /**
     * Get SSO authorization URL for enterprise connections
     */
    public function getSSOAuthorizationUrl(string $connectionId, ?string $state = null): string
    {
        if (!$this->isConfigured()) {
            throw new \RuntimeException('WorkOS is not configured.');
        }

        if ($state === null) {
            $state = $this->generateState();
        }

        Craft::$app->getSession()->set('workos_oauth_state', $state);

        $sso = new SSO();

        return $sso->getAuthorizationUrl(
            null,
            $this->redirectUri,
            $state,
            null,
            $connectionId,
            null
        );
    }

    /**
     * Handle SSO callback and get profile
     */
    public function handleSSOCallback(string $code): array
    {
        if (!$this->isConfigured()) {
            throw new \RuntimeException('WorkOS is not configured.');
        }

        $sso = new SSO();
        $profileAndToken = $sso->getProfileAndToken($code);
        $profile = $profileAndToken->profile;

        return [
            'id' => $profile->id,
            'email' => $profile->email,
            'firstName' => $profile->firstName ?? '',
            'lastName' => $profile->lastName ?? '',
            'idpId' => $profile->idpId ?? null,
            'connectionId' => $profile->connectionId ?? null,
            'connectionType' => $profile->connectionType ?? null,
            'organizationId' => $profile->organizationId ?? null,
            'rawAttributes' => $profile->rawAttributes ?? [],
            'accessToken' => $profileAndToken->accessToken ?? null,
        ];
    }

    /**
     * Validate the OAuth state parameter
     */
    public function validateState(string $state): bool
    {
        $storedState = Craft::$app->getSession()->get('workos_oauth_state');

        if ($storedState === null || $state !== $storedState) {
            return false;
        }

        Craft::$app->getSession()->remove('workos_oauth_state');

        return true;
    }

    /**
     * Generate a random state parameter for CSRF protection
     */
    private function generateState(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Get the redirect URI
     */
    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    /**
     * Get the client ID
     */
    public function getClientId(): ?string
    {
        return $this->clientId;
    }
}
