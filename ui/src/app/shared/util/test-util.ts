import { Observable, of } from 'rxjs';
import { UserProfile } from '../services/auth.service';

export class MockAuthService {

    admin: Observable<boolean> = of(false);

    userProfile: Observable<UserProfile> = of({ userName: '', displayName: '', emailAddress: '', admin: false });

}
