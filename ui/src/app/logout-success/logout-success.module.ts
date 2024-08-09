import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LogoutSuccessComponent } from './logout-success.component';
import { LogoutSuccessRoutingModule } from './logout-success-routing.module';
import { TranslateModule } from '@ngx-translate/core';

@NgModule({
    imports: [
        CommonModule,
        LogoutSuccessRoutingModule,
        TranslateModule
    ],
    declarations: [LogoutSuccessComponent]
})
export class LogoutSuccessModule {
}
