# WorkOS Auth for Craft CMS

A Craft CMS plugin that integrates [WorkOS](https://workos.com) AuthKit and SSO for Control Panel authentication.

## Features

- **AuthKit Integration** - Use WorkOS's pre-built authentication UI
- **SSO Support** - Enterprise SSO with SAML, OIDC, and more
- **Multiple OAuth Providers** - Google, Microsoft, GitHub, Apple
- **User Management** - Auto-create users, sync profiles, manage permissions
- **Directory Sync** - Webhook support for user provisioning
- **Flexible Configuration** - UI settings or environment variables

## Requirements

- Craft CMS 4.0+
- PHP 8.0+
- WorkOS account with API credentials

## Installation

### Via Composer (Private Repository)

Add the repository to your project's `composer.json`:

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "git@github.com:your-org/craft-workos-auth.git"
        }
    ]
}
```

Then require the package:

```bash
composer require workos/craft-workos-auth
```

Install the plugin:

```bash
php craft plugin/install workos-auth
```

## Configuration

### Environment Variables

Add these to your `.env` file:

```env
WORKOS_CLIENT_ID=client_xxxxx
WORKOS_API_KEY=sk_xxxxx
WORKOS_REDIRECT_URI=https://yoursite.com/workos-auth/callback
WORKOS_WEBHOOK_SECRET=xxxxx  # Optional, for directory sync
```

### Plugin Settings

Navigate to **Settings → Plugins → WorkOS Auth** in the Control Panel to configure:

- **Enable/Disable** - Toggle WorkOS authentication
- **Replace Default Login** - Hide Craft's login form, show only WorkOS
- **Authentication Provider** - AuthKit, Google, Microsoft, etc.
- **Auto-Create Users** - Create Craft users for new WorkOS users
- **Allowed Domains** - Restrict login to specific email domains
- **Admin Domains** - Auto-grant admin access to specific domains
- **Default User Group** - Assign new users to a group

### WorkOS Dashboard Setup

1. Create a WorkOS account at [workos.com](https://workos.com)
2. Create an application and note your Client ID and API Key
3. Add your redirect URI: `https://yoursite.com/workos-auth/callback`
4. Configure authentication methods (AuthKit, OAuth providers, SSO connections)

## Usage

Once configured, users will see a "Sign in with SSO" button on the Craft login page. If "Replace Default Login" is enabled, they'll be automatically redirected to WorkOS.

### Webhooks (Optional)

For Directory Sync, configure a webhook in WorkOS pointing to:

```
https://yoursite.com/workos-auth/webhook
```

Set your webhook secret in the plugin settings or via `WORKOS_WEBHOOK_SECRET`.

## Security

- CSRF protection via OAuth state parameter
- Open redirect prevention on return URLs
- Webhook signature verification
- Session regeneration on login
- Debug mode for development (disable in production)

## License

MIT
