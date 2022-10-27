import { Component, OnInit } from '@angular/core';
import { NutroService } from 'src/app/services/nutro.service';

@Component({
  selector: 'app-quickanswer',
  templateUrl: './quickanswer.component.html',
  styleUrls: ['./quickanswer.component.css'],
})
export class QuickanswerComponent implements OnInit {
  constructor(private nutroService: NutroService) {}

  query: string = '';

  answer: string = '';
  image: string = '';
  showAnswer: boolean = false;

  ngOnInit(): void {}

  onClick() {
    if (this.query.length >= 5) {
      this.nutroService.fetchQuickAnswer(this.query).subscribe((res: any) => {
        if (res.success) {
          this.answer = res.answer;
          this.image = res.image || '';
        } else {
          this.answer = 'Ask the correct question !';
          this.image = '';
        }
      });
    }
  }
}