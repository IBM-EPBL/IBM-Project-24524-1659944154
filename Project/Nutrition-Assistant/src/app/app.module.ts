import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { NavbarComponent } from './components/navbar/navbar.component';
import { HomeComponent } from './components/home/home.component';
import { ChillaxComponent } from './components/chillax/chillax.component';
import { QuickanswerComponent } from './components/quickanswer/quickanswer.component';
import { NutbydishComponent } from './components/nutbydish/nutbydish.component';
import { HttpClientModule } from '@angular/common/http';
import { ResbycalComponent } from './components/resbycal/resbycal.component';
import { ConvertamountComponent } from './components/convertamount/convertamount.component';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

@NgModule({
  declarations: [
    AppComponent,
    NavbarComponent,
    HomeComponent,
    ChillaxComponent,
    QuickanswerComponent,
    NutbydishComponent,
    ResbycalComponent,
    ConvertamountComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule,
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
