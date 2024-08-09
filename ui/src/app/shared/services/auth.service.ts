import { Injectable } from '@angular/core';
import { BehaviorSubject, firstValueFrom, Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { HttpClient } from '@angular/common/http';
import { ReplayContainer } from './services-common';
import { Router } from '@angular/router';

export interface UserProfile {

    userName: string;

    displayName: string;

    emailAddress: string;

    admin: boolean;

}

@Injectable({ providedIn: 'root' })
export class AuthService {

    authenticated: Observable<boolean>;

    admin: Observable<boolean>;

    userProfile: Observable<UserProfile>;

    showBounceBubbles = new BehaviorSubject<boolean>(false);

    private userProfileRequest = new ReplayContainer<UserProfile>(() => this.http.get('/api/me?returnEmpty=true'));


    constructor(private http: HttpClient, private router: Router) {
        this.userProfile = this.userProfileRequest.getObservable();

        this.authenticated = this.userProfile.pipe(map(p => !!p.userName));
        this.admin = this.userProfile.pipe(map(p => p.admin));
    }

    async checkAuthenticated(): Promise<boolean> {
        await this.userProfileRequest.refresh();
        return firstValueFrom(this.authenticated);
    }

    async logout() {
        // a little trick - FIRST navigate to that page, THEN logout (there)
        // otherwise, we would get an error because static protected resources would be tried to be loaded.
        return this.router.navigateByUrl('/logout-success');
    }

}
