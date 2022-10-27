import { Component, OnInit } from '@angular/core';
import { NutroService } from 'src/app/services/nutro.service';

@Component({
  selector: 'app-chillax',
  templateUrl: './chillax.component.html',
  styleUrls: ['./chillax.component.css']
})
export class ChillaxComponent implements OnInit {

  joke: string = '';

  trivia: string = '';

  constructor(private nutroService: NutroService) {}

  ngOnInit(): void {

  }
  onGetJoke() {
    this.joke = '';
    this.nutroService.fetchRandomJoke().subscribe((res: any) => {
      if (res.success) {
        this.joke = res.text;
      } else {
        this.joke = 'Joke unavailable !';
      }
    });
  }

  onGetTrivia() {
    this.trivia = '';
    this.nutroService.fetchRandomtrivia().subscribe((res: any) => {
      if (res.success) {
        this.trivia = res.text;
      } else {
        this.trivia = 'Trivia unavailable !';
      }
    });
  }

}
