import { Component, OnInit } from '@angular/core';
import { NutroService } from 'src/app/services/nutro.service';


@Component({
  selector: 'app-nutbydish',
  templateUrl: './nutbydish.component.html',
  styleUrls: ['./nutbydish.component.css']
})
export class NutbydishComponent implements OnInit {
  name: string = '';
  cal: number = 0;
  pro: number = 0;
  car: number = 0;
  fat: number = 0;
  msg: string = '';

  constructor(private nutroService:NutroService) { }
  onclick() {
    if (this.name.length >= 5) {
      this.nutroService
        .fetchNutritionByDish(this.name)
        .subscribe((res: any) => {
          if (true) {
            if (res.hasOwnProperty('calories')) {
              this.cal = res.calories.value;
            }
            if (res.hasOwnProperty('protein')) {
              this.pro = res.protein.value;
            }
            if (res.hasOwnProperty('carbs')) {
              this.car = res.carbs.value;
            }
            if (res.hasOwnProperty('fat')) {
              this.fat = res.fat.value;
            } else {
              this.msg = 'NO UNIT !';
            }
          }
        });
    }
  }

  ngOnInit(): void {
  }

}

