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

Add the repository to your `composer.json`:

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/legion-collective/craft-workos-auth.git"
        }
    ],
    "require": {
        "workos/craft-workos-auth": "^1.0"
    }
}
```

Then run:

```bash
composer update
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

| Setting | Description |
|---------|-------------|
| **Enable/Disable** | Toggle WorkOS authentication |
| **Debug Mode** | Show detailed errors (disable in production) |
| **Replace Default Login** | Hide Craft's login form, show only WorkOS |
| **Login Button Text** | Customize the SSO button text |
| **Authentication Provider** | AuthKit, Google, Microsoft, GitHub, Apple |
| **Connection ID** | For enterprise SSO connections |
| **Organization ID** | For organization-scoped auth |
| **Auto-Create Users** | Create Craft users for new WorkOS users |
| **Update User on Login** | Sync profile data on each login |
| **Default User Group** | Assign new users to a group |
| **Allowed Domains** | Restrict login to specific email domains |
| **Admin Domains** | Auto-grant admin access to specific domains |

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

Supported events:
- `dsync.user.created` - Creates new Craft user
- `dsync.user.updated` - Updates user profile
- `dsync.user.deleted` - Suspends user account
- `user.created` / `user.updated` / `user.deleted` - User Management events

## Security

- CSRF protection via OAuth state parameter
- Open redirect prevention on return URLs
- Webhook signature verification (HMAC-SHA256)
- Session regeneration on login
- Generic error messages by default (detailed in debug mode)
- Domain-based access control

## Troubleshooting

### Redirect Loop After Login

Check that your `WORKOS_REDIRECT_URI` doesn't include `/admin`:
- ✅ `https://yoursite.com/workos-auth/callback`
- ❌ `https://yoursite.com/admin/workos-auth/callback`

### "WorkOS is not configured" Error

Ensure your environment variables are set:
```bash
php craft env
# Should show WORKOS_CLIENT_ID and WORKOS_API_KEY
```

### User Can't Log In

1. Check "Allowed Domains" setting - user's email domain must match
2. Check if user account is suspended or locked in Craft
3. Enable Debug Mode to see detailed error messages

## License

MIT
