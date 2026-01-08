<?php

namespace workosauth\models;

use craft\base\Model;

/**
 * WorkOS Auth Settings Model
 */
class Settings extends Model
{
    /**
     * @var bool Enable/disable WorkOS authentication
     */
    public bool $enabled = true;

    /**
     * @var bool Debug mode - shows detailed error messages when enabled
     */
    public bool $debug = false;

    /**
     * @var bool Replace the default Craft login page with WorkOS-only authentication
     */
    public bool $replaceDefaultLogin = false;

    /**
     * @var string|null Default user group handle for newly created users
     */
    public ?string $defaultUserGroup = null;

    /**
     * @var string Comma-separated list of allowed email domains
     */
    public string $allowedDomains = '';

    /**
     * @var string Comma-separated list of admin email domains
     */
    public string $adminEmailDomains = '';

    /**
     * @var bool Automatically create new Craft users when they authenticate via WorkOS
     */
    public bool $autoCreateUsers = false;

    /**
     * @var bool Update user profile from WorkOS on each login
     */
    public bool $updateUserOnLogin = true;

    /**
     * @var string Custom text for the WorkOS login button
     */
    public string $loginButtonText = 'Sign in with SSO';

    /**
     * @var string|null WorkOS organization ID
     */
    public ?string $organizationId = null;

    /**
     * @var string|null Default SSO connection ID
     */
    public ?string $connectionId = null;

    /**
     * @var string|null OAuth provider (authkit, GoogleOAuth, MicrosoftOAuth, etc.)
     */
    public ?string $provider = 'authkit';

    /**
     * @var string|null WorkOS Client ID (falls back to WORKOS_CLIENT_ID env var)
     */
    public ?string $clientId = null;

    /**
     * @var string|null WorkOS API Key (falls back to WORKOS_API_KEY env var)
     */
    public ?string $apiKey = null;

    /**
     * @var string|null OAuth Redirect URI (falls back to WORKOS_REDIRECT_URI env var)
     */
    public ?string $redirectUri = null;

    /**
     * @var string|null Webhook Secret (falls back to WORKOS_WEBHOOK_SECRET env var)
     */
    public ?string $webhookSecret = null;

    /**
     * @inheritdoc
     */
    protected function defineRules(): array
    {
        return [
            [['enabled', 'debug', 'replaceDefaultLogin', 'autoCreateUsers', 'updateUserOnLogin'], 'boolean'],
            [['defaultUserGroup', 'allowedDomains', 'adminEmailDomains', 'loginButtonText', 'organizationId', 'connectionId', 'provider', 'clientId', 'apiKey', 'redirectUri', 'webhookSecret'], 'string'],
            ['loginButtonText', 'default', 'value' => 'Sign in with SSO'],
            ['provider', 'default', 'value' => 'authkit'],
        ];
    }

    /**
     * Get the WorkOS Client ID (from settings or env)
     */
    public function getClientId(): ?string
    {
        if (!empty($this->clientId)) {
            return \Craft::parseEnv($this->clientId);
        }
        return \Craft::parseEnv('$WORKOS_CLIENT_ID');
    }

    /**
     * Get the WorkOS API Key (from settings or env)
     */
    public function getApiKey(): ?string
    {
        if (!empty($this->apiKey)) {
            return \Craft::parseEnv($this->apiKey);
        }
        return \Craft::parseEnv('$WORKOS_API_KEY');
    }

    /**
     * Get the OAuth Redirect URI (from settings or env)
     */
    public function getRedirectUri(): ?string
    {
        if (!empty($this->redirectUri)) {
            return \Craft::parseEnv($this->redirectUri);
        }
        return \Craft::parseEnv('$WORKOS_REDIRECT_URI');
    }

    /**
     * Get the Webhook Secret (from settings or env)
     */
    public function getWebhookSecret(): ?string
    {
        if (!empty($this->webhookSecret)) {
            return \Craft::parseEnv($this->webhookSecret);
        }
        return \Craft::parseEnv('$WORKOS_WEBHOOK_SECRET');
    }

    /**
     * Get allowed domains as an array
     */
    public function getAllowedDomainsArray(): array
    {
        if (empty($this->allowedDomains)) {
            return [];
        }
        return array_map('trim', explode(',', $this->allowedDomains));
    }

    /**
     * Get admin email domains as an array
     */
    public function getAdminEmailDomainsArray(): array
    {
        if (empty($this->adminEmailDomains)) {
            return [];
        }
        return array_map('trim', explode(',', $this->adminEmailDomains));
    }
}
