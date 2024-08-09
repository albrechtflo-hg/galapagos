import { Component, OnInit } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { HttpClient } from '@angular/common/http';

@Component({
    selector: 'app-logout-success',
    templateUrl: './logout-success.component.html',
    styleUrls: ['./logout-success.component.scss']
})
export class LogoutSuccessComponent implements OnInit {

    constructor(private http: HttpClient) {
    }

    async ngOnInit() {
        const httpOptions = {
            headers: {
                // eslint-disable-next-line @typescript-eslint/naming-convention
                'Accept': 'text/html',
                'Content-Type': 'application/json'
            },
            responseType: 'text' as const
        };
        await firstValueFrom(this.http.post('/logout', '', httpOptions));
    }

}
