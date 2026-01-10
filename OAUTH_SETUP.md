# OAuth Authentication Setup Guide

This guide explains how to enable OAuth authentication in reNgine-ng using multiple providers: Google, GitHub, Microsoft, and generic OAuth2.

## What Was Changed

### 1. Dependencies
- Added `django-allauth = "0.54.0"` to [docker/web/pyproject.toml](docker/web/pyproject.toml)

### 2. Settings Configuration
Updated [web/reNgine/settings.py](web/reNgine/settings.py):
- Added `django.contrib.sites` to INSTALLED_APPS
- Added allauth apps: `allauth`, `allauth.account`, `allauth.socialaccount`
- Added provider apps: `google`, `github`, `microsoft`
- Configured `SITE_ID = 1`
- Added authentication backends to support both traditional and OAuth login
- Configured allauth settings for flexible authentication
- Added OAuth provider configurations with environment variables for all providers

### 3. URL Configuration
Updated [web/reNgine/urls.py](web/reNgine/urls.py):
- Added `path('accounts/', include('allauth.urls'))` for OAuth endpoints

### 4. Environment Variables
Updated [.env-dist](.env-dist):
- Added credentials for Google, GitHub, Microsoft OAuth providers

### 5. Login Template
Updated [web/templates/base/login.html](web/templates/base/login.html):
- Added OAuth login buttons for Google, GitHub, and Microsoft below the standard login form

## Setup Instructions

### Step 1: Install Dependencies
If running from source, rebuild the Docker images:
```bash
cd docker
docker-compose build web celery
```

Or if using Poetry directly:
```bash
cd web
poetry add django-allauth
```

### Step 2: Configure OAuth Providers

You can enable one or more OAuth providers. Configure only the ones you plan to use.

#### Google OAuth

1. **Create a Google Cloud Project**:
   - Go to https://console.cloud.google.com/
   - Create a new project or select an existing one

2. **Enable Google+ API**:
   - Navigate to "APIs & Services" > "Library"
   - Search for "Google+ API" and enable it

3. **Create OAuth Credentials**:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Web application"
   - Add authorized redirect URIs:
     - For local: `http://localhost:8000/accounts/google/login/callback/`
     - For production: `https://your-domain.com/accounts/google/login/callback/`
   - Copy the Client ID and Client Secret

4. **Update Environment Variables**:
   ```bash
   GOOGLE_OAUTH_CLIENT_ID=your-client-id-here.apps.googleusercontent.com
   GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret-here
   ```

#### GitHub OAuth

1. **Create GitHub OAuth App**:
   - Go to https://github.com/settings/developers
   - Click "New OAuth App"
   - Fill in the details:
     - Application name: reNgine-ng
     - Homepage URL: `http://localhost:8000` or `https://your-domain.com`
     - Authorization callback URL: `http://localhost:8000/accounts/github/login/callback/`
   - Click "Register application"
   - Copy the Client ID and generate a Client Secret

2. **Update Environment Variables**:
   ```bash
   GITHUB_OAUTH_CLIENT_ID=your-github-client-id
   GITHUB_OAUTH_CLIENT_SECRET=your-github-client-secret
   ```

#### Microsoft OAuth

1. **Register Application in Azure**:
   - Go to https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps
   - Click "New registration"
   - Fill in the details:
     - Name: reNgine-ng
     - Supported account types: Choose based on your needs
     - Redirect URI: Web - `http://localhost:8000/accounts/microsoft/login/callback/`
   - Click "Register"

2. **Create Client Secret**:
   - Go to "Certificates & secrets"
   - Click "New client secret"
   - Add description and set expiration
   - Copy the secret value immediately

3. **Update Environment Variables**:
   ```bash
   MICROSOFT_OAUTH_CLIENT_ID=your-application-id
   MICROSOFT_OAUTH_CLIENT_SECRET=your-client-secret-value
   ```

#### GitLab OAuth (Self-hosted or gitlab.com)

For self-hosted GitLab or gitlab.com:

1. **Create Application in GitLab**:
   - Go to User Settings > Applications (or Admin Area > Applications for instance-wide)
   - Fill in the details:
     - Name: reNgine-ng
     - Redirect URI: `http://localhost:8000/accounts/gitlab/login/callback/`
     - Scopes: Select `read_user` (minimum required)
   - Click "Save application"
   - Copy the Application ID and Secret

2. **Update Environment Variables**:
   ```bash
   # For self-hosted GitLab, change the URL
   GITLAB_URL=https://gitlab.yourcompany.com
   # For gitlab.com, use default:
   # GITLAB_URL=https://gitlab.com
   
   GITLAB_OAUTH_CLIENT_ID=your-application-id
   GITLAB_OAUTH_CLIENT_SECRET=your-secret
   ```

#### Generic OpenID Connect (Keycloak, Okta, Auth0, etc.)

For any OpenID Connect (OIDC) compliant provider:

**Method 1: Via Django Admin (Recommended for self-hosted)**

1. **Run migrations first**:
   ```bash
   docker-compose exec web python manage.py migrate
   ```

2. **Login to Django Admin**:
   - Go to `http://localhost:8000/admin/`
   - Navigate to "Sites" → "Social applications"
   - Click "Add Social Application"

3. **Configure the provider**:
   - Provider: Select "OpenID Connect"
   - Provider ID: `openid_connect` (or custom like `keycloak`, `okta`)
   - Name: Your provider name (e.g., "Company SSO")
   - Client ID: From your OIDC provider
   - Secret: From your OIDC provider
   - Settings (JSON format):
     ```json
     {
       "server_url": "https://your-oidc-server.com/.well-known/openid-configuration"
     }
     ```
   - Sites: Select your site
   - Click "Save"

4. **Example for Keycloak**:
   ```json
   {
     "server_url": "https://keycloak.yourcompany.com/realms/your-realm/.well-known/openid-configuration"
   }
   ```

5. **Example for Okta**:
   ```json
   {
     "server_url": "https://your-domain.okta.com/.well-known/openid-configuration"
   }
   ```

**Method 2: Environment Variables (Alternative)**

For simple OIDC setups, you can add to settings.py:
```python
'openid_connect': {
    'APPS': [
        {
            'provider_id': 'your-sso',
            'name': 'Company SSO',
            'client_id': env('OIDC_CLIENT_ID', default=''),
            'secret': env('OIDC_SECRET', default=''),
            'settings': {
                'server_url': env('OIDC_SERVER_URL', default='')
            }
        }
    ]
}
```

### Step 3: Run Migrations
After setting up, run migrations to create the necessary database tables:
```bash
docker-compose exec web python manage.py migrate
```

Or if running locally:
```bash
python manage.py migrate
```

### Step 4: Configure Site Domain
The django-allauth requires the Site domain to be set correctly:

```bash
docker-compose exec web python manage.py shell
```

Then in the Python shell:
```python
from django.contrib.sites.models import Site
site = Site.objects.get_current()
site.domain = 'localhost:8000'  # or your production domain
site.name = 'reNgine-ng'
site.save()
```

Or use Django admin:
- Login to `/admin/`
- Go to "Sites"
- Edit the default site to match your domain

## How It Works

1. **User clicks an OAuth provider button** (e.g., "Sign in with Google") on the login page
2. **Redirected to the provider** for authentication
3. **User authorizes the app** on the provider's consent screen
4. **Provider redirects back** to reNgine-ng with an authorization code
5. **django-allauth processes the callback**:
   - Exchanges code for access token
   - Retrieves user profile from the provider
   - Creates or updates user account in reNgine-ng
   - Logs the user in
6. **User is redirected** to the onboarding page (configured via `LOGIN_REDIRECT_URL`)

## Supported Providers

- ✅ **Google**: Sign in with Google account
- ✅ **GitHub**: Sign in with GitHub account
- ✅ **Microsoft**: Sign in with Microsoft/Azure AD account
- ✅ **GitLab**: Self-hosted or gitlab.com
- ✅ **OpenID Connect**: Generic OIDC support for self-hosted OAuth servers (Keycloak, Okta, Auth0, etc.)
- 📝 **Additional providers**: Can be added individually (see "Adding More OAuth Providers" section)

## Key Features

- ✅ **Preserves existing authentication**: Username/password login still works
- ✅ **Automatic account creation**: New users are created automatically on first OAuth login
- ✅ **Account linking**: Existing users can link their Google account
- ✅ **Flexible email verification**: Email verification is optional
- ✅ **Secure**: Uses environment variables for secrets
- ✅ **Simple**: Minimal configuration required

## Verification Checklist

### Pre-deployment Checks
- [ ] `django-allauth` added to dependencies
- [ ] OAuth buttons appear on login page (Google, GitHub, Microsoft)
- [ ] Clicking each OAuth button redirects to correct provider
- [ ] After authorizing, user is redirected back to reNgine-ng
- [ ] New user account is created automatically
- [ ] User is logged in and redirected to onboarding page
- [ ] Existing users can link OAuth accounts via admin panel
- [ ] All enabled providers work correctly
- [ ] Traditional login (username/password) still works
- [ ] "Sign in with Google" button appears on login page
- [ ] Clicking Google button redirects to Google OAuth consent screen
- [ ] After authorizing, user is redirected back to reNgine-ng
- [ ] New user account is created automatically
- [ ] User is logged in and redirected to onboarding page
- [ ] Existing users can link Google account via admin panel

### Security Checks
- [ ] OAuth credentials stored in environment variables (not hardcoded)
- [ ] Redirect URIs configured correctly in Google Cloud Console
- [ ] HTTPS enabled in production
- [ ] `DOMAIN_NAME` set correctly for production

## Adding More OAuth Providers
django-allauth supports 50+ providers. To add another provider:

1. **Add the provider to INSTALLED_APPS** in settings.py:
   ```python
   'allauth.socialaccount.providers.gitlab',
   ```

2. **Configure provider settings** in settings.py:
   ```python
   'gitlab': {
       'SCOPE': ['read_user'],
       'APP': {
           'client_id': env('GITLAB_OAUTH_CLIENT_ID', default=''),
           'secret': env('GITLAB_OAUTH_CLIENT_SECRET', default=''),
       }
   }
   ```

3. **Add environment variables** to `.env`

4. **Add button to login template**:
   ```html
   <a href="{% url 'gitlab_login' %}" class="btn btn-outline-secondary">
     <i class="mdi mdi-gitlab"></i> Sign in with GitLab
   </a>
   ```

Supported providers include: Twitter, Facebook, LinkedIn, Bitbucket, Stack Overflow, GitLab, and many more.

See [django-allauth documentation](https://django-allauth.readthedocs.io/en/latest/providers.html) for the complete list
See [django-allauth documentation](https://django-allauth.readthedocs.io/) for supported providers.

## Troubleshooting

### "Social app for Google not found"
- Make sure Site domain is configured correctly
- Run migrations: `python manage.py migrate`
- Check that `SITE_ID = 1` in settings.py

### Redirect URI mismatch
- Ensure the redirect URI in Google Cloud Console matches exactly
- Format: `https://your-domain.com/accounts/google/login/callback/`
- Include trailing slash

### User created but not logged in
- Check `LOGIN_REDIRECT_URL` setting
- Verify that the user has necessary permissions
- Check for middleware conflicts with `login_required.middleware.LoginRequiredMiddleware`

### OAuth button doesn't appear
- OAuth buttons only show if providers are properly configured
- Check that credentials are set in `.env` file
- Run migrations to create allauth tables
- Clear browser cache and restart the server
- Check template syntax and verify static files are served correctly

### Template error: "Invalid block tag on line X: 'provider_login_url'"
- Ensure `{% load socialaccount %}` is at the top of the template
- Verify django-allauth is properly installed
- Run `docker-compose build web` to rebuild with new dependencies

### ImportError or ModuleNotFoundError for allauth
- Rebuild Docker containers: `docker-compose build web celery`
- Or install locally: `poetry add django-allauth`
- Verify the package is in pyproject.toml

## Production Considerations

1. **Use HTTPS**: OAuth requires secure connections in production
2. **Secure secrets**: Never commit `.env` file with real credentials
3. **Configure ALLOWED_HOSTS**: Set properly for your domain
4. **Email configuration**: Set up email backend for account notifications
5. **Rate limiting**: Consider adding rate limiting for OAuth endpoints
6. **Monitoring**: Log OAuth authentication events
7. **Database backup**: Back up before running migrations
8. **Test thoroughly**: Test all OAuth flows in staging before production

## Common Issues and Fixes

### Issue: "CSRF verification failed" during OAuth callback
**Solution**: Ensure `django.middleware.csrf.CsrfViewMiddleware` is in MIDDLEWARE and comes after SessionMiddleware

### Issue: OAuth works locally but fails in production
**Solution**: 
- Verify redirect URIs in OAuth provider console match production domain
- Ensure HTTPS is properly configured
- Check that `DOMAIN_NAME` in settings matches your actual domain

### Issue: Users created via OAuth can't access certain features
**Solution**: Check role/permission settings. OAuth users may need default roles assigned.

## References

- [django-allauth documentation](https://django-allauth.readthedocs.io/)
- [Google OAuth setup guide](https://developers.google.com/identity/protocols/oauth2)
- [GitHub OAuth Apps](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
- [Django Sites framework](https://docs.djangoproject.com/en/3.2/ref/contrib/sites/)
