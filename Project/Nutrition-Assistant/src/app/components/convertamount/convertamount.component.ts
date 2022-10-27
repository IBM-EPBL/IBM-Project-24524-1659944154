import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { NutroService } from 'src/app/services/nutro.service';

@Component({
  selector: 'app-convertamount',
  templateUrl: './convertamount.component.html',
  styleUrls: ['./convertamount.component.css'],
})
export class ConvertamountComponent implements OnInit {
  convertForm: FormGroup = new FormGroup({
    ingredientName: new FormControl('', [Validators.required]),
    targetUnit: new FormControl('', [Validators.required]),
    sourceUnit: new FormControl('', [Validators.required]),
    sourceAmount: new FormControl('', [Validators.required, Validators.min(0)]),
  });

  answer: string = '';

  constructor(private nutroService: NutroService) {}

  ngOnInit(): void {}

  onSubmit() {
    this.answer = '';
    if (this.convertForm.valid) {
      const values = this.convertForm.value;
      this.nutroService
        .fetchConvertAmount(
          values.ingredientName,
          values.targetUnit,
          values.sourceUnit,
          values.sourceAmount
        )
        .subscribe((res: any) => {
          if (res.hasOwnProperty('answer')) {
            this.answer = res.answer;
          } else {
            this.answer = 'Enter valid units !';
          }
        });
    }
  }
}
