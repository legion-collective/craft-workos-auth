<?php

namespace workosauth\controllers;

use Craft;
use craft\elements\User;
use craft\web\Controller;
use workosauth\Plugin;
use yii\web\Response;
use yii\web\BadRequestHttpException;

/**
 * Webhook Controller
 *
 * Handles WorkOS webhook events for Directory Sync and User Management.
 */
class WebhookController extends Controller
{
    /**
     * @inheritdoc
     */
    protected array|bool|int $allowAnonymous = ['handle'];

    /**
     * @inheritdoc
     */
    public $enableCsrfValidation = false;

    /**
     * Handle incoming webhook from WorkOS
     */
    public function actionHandle(): Response
    {
        $request = Craft::$app->getRequest();
        $payload = $request->getRawBody();

        if (empty($payload)) {
            throw new BadRequestHttpException('Empty payload');
        }

        $settings = Plugin::getInstance()?->getSettings();
        $webhookSecret = $settings?->getWebhookSecret() ?? Craft::parseEnv('$WORKOS_WEBHOOK_SECRET');
        if (!$webhookSecret) {
            Craft::error('Webhook secret not configured - webhooks disabled for security', __METHOD__);
            throw new BadRequestHttpException('Webhook not configured');
        }

        $signature = $request->getHeaders()->get('workos-signature');
        if (!$this->verifySignature($payload, $signature, $webhookSecret)) {
            Craft::warning('Invalid webhook signature', __METHOD__);
            throw new BadRequestHttpException('Invalid signature');
        }

        $event = json_decode($payload, true);

        if (!$event || !isset($event['event'])) {
            throw new BadRequestHttpException('Invalid event format');
        }

        $eventType = $event['event'];
        $data = $event['data'] ?? [];

        Craft::info("Received WorkOS webhook: {$eventType}", __METHOD__);

        try {
            switch ($eventType) {
                case 'dsync.user.created':
                    $this->handleUserCreated($data);
                    break;
                case 'dsync.user.updated':
                    $this->handleUserUpdated($data);
                    break;
                case 'dsync.user.deleted':
                    $this->handleUserDeleted($data);
                    break;
                case 'user.created':
                    $this->handleUserManagementCreated($data);
                    break;
                case 'user.updated':
                    $this->handleUserManagementUpdated($data);
                    break;
                case 'user.deleted':
                    $this->handleUserManagementDeleted($data);
                    break;
                default:
                    Craft::info("Unhandled webhook event type: {$eventType}", __METHOD__);
            }
        } catch (\Exception $e) {
            Craft::error("Error processing webhook: " . $e->getMessage(), __METHOD__);
            return $this->asJson(['success' => false, 'error' => $e->getMessage()]);
        }

        return $this->asJson(['success' => true]);
    }

    /**
     * Verify webhook signature
     */
    private function verifySignature(string $payload, ?string $signature, string $secret): bool
    {
        if (!$signature) {
            return false;
        }

        $parts = [];
        foreach (explode(',', $signature) as $part) {
            [$key, $value] = explode('=', $part, 2);
            $parts[$key] = $value;
        }

        if (!isset($parts['t']) || !isset($parts['v1'])) {
            return false;
        }

        $timestamp = $parts['t'];
        $expectedSignature = $parts['v1'];

        if (abs(time() - (int)$timestamp) > 300) {
            return false;
        }

        $signedPayload = "{$timestamp}.{$payload}";
        $computedSignature = hash_hmac('sha256', $signedPayload, $secret);

        return hash_equals($computedSignature, $expectedSignature);
    }

    /**
     * Handle directory sync user created event
     */
    private function handleUserCreated(array $data): void
    {
        $email = $data['emails'][0]['value'] ?? null;

        if (!$email) {
            Craft::warning('Directory sync user created without email', __METHOD__);
            return;
        }

        $plugin = Plugin::getInstance();
        $settings = $plugin->getSettings();

        if (!$plugin->isAllowedDomain($email)) {
            Craft::info("Skipping user creation for unauthorized domain: {$email}", __METHOD__);
            return;
        }

        $existingUser = User::find()->email($email)->status(null)->one();
        if ($existingUser) {
            Craft::info("User already exists for: {$email}", __METHOD__);
            return;
        }

        $user = new User();
        $user->email = $email;
        $user->username = $email;
        $user->firstName = $data['firstName'] ?? '';
        $user->lastName = $data['lastName'] ?? '';
        $user->newPassword = Craft::$app->getSecurity()->generateRandomString(32);
        $user->pending = false;

        if ($plugin->isAdminDomain($email)) {
            $user->admin = true;
        }

        if (Craft::$app->getElements()->saveElement($user)) {
            if ($settings->defaultUserGroup) {
                $group = Craft::$app->getUserGroups()->getGroupByHandle($settings->defaultUserGroup);
                if ($group) {
                    Craft::$app->getUsers()->assignUserToGroups($user->id, [$group->id]);
                }
            }
            Craft::info("Created user from directory sync: {$email}", __METHOD__);
        } else {
            Craft::error("Failed to create user: " . implode(', ', $user->getErrorSummary(true)), __METHOD__);
        }
    }

    /**
     * Handle directory sync user updated event
     */
    private function handleUserUpdated(array $data): void
    {
        $email = $data['emails'][0]['value'] ?? null;

        if (!$email) {
            return;
        }

        $user = User::find()->email($email)->status(null)->one();

        if (!$user) {
            $this->handleUserCreated($data);
            return;
        }

        $changed = false;

        if (!empty($data['firstName']) && $user->firstName !== $data['firstName']) {
            $user->firstName = $data['firstName'];
            $changed = true;
        }

        if (!empty($data['lastName']) && $user->lastName !== $data['lastName']) {
            $user->lastName = $data['lastName'];
            $changed = true;
        }

        $state = $data['state'] ?? null;
        if ($state === 'suspended' && !$user->suspended) {
            $user->suspended = true;
            $changed = true;
        } elseif ($state === 'active' && $user->suspended) {
            $user->suspended = false;
            $changed = true;
        }

        if ($changed) {
            if (Craft::$app->getElements()->saveElement($user)) {
                Craft::info("Updated user from directory sync: {$email}", __METHOD__);
            }
        }
    }

    /**
     * Handle directory sync user deleted event
     */
    private function handleUserDeleted(array $data): void
    {
        $email = $data['emails'][0]['value'] ?? null;

        if (!$email) {
            return;
        }

        $user = User::find()->email($email)->status(null)->one();

        if (!$user) {
            return;
        }

        $user->suspended = true;

        if (Craft::$app->getElements()->saveElement($user)) {
            Craft::info("Suspended user from directory sync delete: {$email}", __METHOD__);
        }
    }

    /**
     * Handle User Management user created event
     */
    private function handleUserManagementCreated(array $data): void
    {
        $email = $data['email'] ?? null;

        if (!$email) {
            return;
        }

        $plugin = Plugin::getInstance();
        $settings = $plugin->getSettings();

        if (!$plugin->isAllowedDomain($email)) {
            return;
        }

        $existingUser = User::find()->email($email)->status(null)->one();
        if ($existingUser) {
            return;
        }

        $user = new User();
        $user->email = $email;
        $user->username = $email;
        $user->firstName = $data['firstName'] ?? $data['first_name'] ?? '';
        $user->lastName = $data['lastName'] ?? $data['last_name'] ?? '';
        $user->newPassword = Craft::$app->getSecurity()->generateRandomString(32);
        $user->pending = false;

        if ($plugin->isAdminDomain($email)) {
            $user->admin = true;
        }

        if (Craft::$app->getElements()->saveElement($user)) {
            if ($settings->defaultUserGroup) {
                $group = Craft::$app->getUserGroups()->getGroupByHandle($settings->defaultUserGroup);
                if ($group) {
                    Craft::$app->getUsers()->assignUserToGroups($user->id, [$group->id]);
                }
            }
            Craft::info("Created user from User Management webhook: {$email}", __METHOD__);
        }
    }

    /**
     * Handle User Management user updated event
     */
    private function handleUserManagementUpdated(array $data): void
    {
        $email = $data['email'] ?? null;

        if (!$email) {
            return;
        }

        $user = User::find()->email($email)->status(null)->one();

        if (!$user) {
            $this->handleUserManagementCreated($data);
            return;
        }

        $changed = false;
        $firstName = $data['firstName'] ?? $data['first_name'] ?? null;
        $lastName = $data['lastName'] ?? $data['last_name'] ?? null;

        if ($firstName && $user->firstName !== $firstName) {
            $user->firstName = $firstName;
            $changed = true;
        }

        if ($lastName && $user->lastName !== $lastName) {
            $user->lastName = $lastName;
            $changed = true;
        }

        if ($changed && Craft::$app->getElements()->saveElement($user)) {
            Craft::info("Updated user from User Management webhook: {$email}", __METHOD__);
        }
    }

    /**
     * Handle User Management user deleted event
     */
    private function handleUserManagementDeleted(array $data): void
    {
        $email = $data['email'] ?? null;

        if (!$email) {
            return;
        }

        $user = User::find()->email($email)->status(null)->one();

        if ($user) {
            $user->suspended = true;
            if (Craft::$app->getElements()->saveElement($user)) {
                Craft::info("Suspended user from User Management webhook: {$email}", __METHOD__);
            }
        }
    }
}
