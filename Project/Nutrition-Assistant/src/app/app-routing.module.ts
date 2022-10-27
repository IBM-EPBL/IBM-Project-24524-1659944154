import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { ChillaxComponent } from './components/chillax/chillax.component';
import { ConvertamountComponent } from './components/convertamount/convertamount.component';
import { HomeComponent } from './components/home/home.component';
import { NutbydishComponent } from './components/nutbydish/nutbydish.component';
import { QuickanswerComponent } from './components/quickanswer/quickanswer.component';
import { ResbycalComponent } from './components/resbycal/resbycal.component';

const routes: Routes = [
  {
    path:' ',
    component:HomeComponent,

  },
  {
    path:'quickanswer',
    component:QuickanswerComponent,

  },
  {
    path:'chillax',
    component:ChillaxComponent,

  },
  {
    path:'convertamount',
    component:ConvertamountComponent,

  },
  {
    path:'nutbydish',
    component:NutbydishComponent,

  },
  {
    path:'resbycal',
    component:ResbycalComponent,

  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
