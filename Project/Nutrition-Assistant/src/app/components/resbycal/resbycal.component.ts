import { Component, OnInit } from '@angular/core';
import { Recepie } from 'src/app/models/recepie.model';
import { NutroService } from 'src/app/services/nutro.service';

@Component({
  selector: 'app-resbycal',
  templateUrl: './resbycal.component.html',
  styleUrls: ['./resbycal.component.css'],
})
export class ResbycalComponent implements OnInit {
  recepies: Recepie[] = [];
  cal: number;
  constructor(private nutroService: NutroService) {}

  ngOnInit(): void {}

  onClick() {
    if (this.cal > 0) {
      this.nutroService
        .fetchRecipeByCalories(this.cal)
        .subscribe((res: any) => {
          this.recepies = res.meals;
        });
    }
  }
}
