import { ActivatedRouteSnapshot, CanActivateFn } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { inject } from '@angular/core';

const AUTH_RELOAD_KEY = '__auth_reload';

export const canActivateRoute: CanActivateFn = async (route: ActivatedRouteSnapshot) => {
    if (!route.url.length) {
        return Promise.resolve(true);
    }
    const authService: AuthService = inject(AuthService);
    const authenticated = await authService.checkAuthenticated();
    const reloadFlag = localStorage.getItem(AUTH_RELOAD_KEY);
    localStorage.removeItem(AUTH_RELOAD_KEY);

    if (!authenticated) {
        // if in local dev mode, do a gentle redirect to the login page
        if (window.location.host.startsWith('localhost:')) {
            window.location.href = '/oauth2/authorization/keycloak';
        } else if (!reloadFlag) {
            localStorage.setItem(AUTH_RELOAD_KEY, 'true');
            window.location.reload();
        }
        return Promise.resolve(false);
    }

    return Promise.resolve(authenticated);
};
