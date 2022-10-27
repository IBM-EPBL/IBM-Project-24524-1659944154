import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root',
})
export class NutroService {
  public static ENDPOINT = 'http://localhost:8070/api';

  constructor(private http: HttpClient) {}

  fetchQuickAnswer(question: string) {
    return this.http.get(
      NutroService.ENDPOINT +
        '/quickanswer?query=' +
        encodeURIComponent(question)
    );
  }

  fetchRandomJoke() {
    return this.http.get(NutroService.ENDPOINT + '/randomjoke');
  }

  fetchRandomtrivia() {
    return this.http.get(NutroService.ENDPOINT + '/randomtrivia');
  }

  fetchConvertAmount(ig: string, tu: string, mt: string, fl: number) {
    return this.http.get(
      NutroService.ENDPOINT +
        '/convert?ingridientsname=' +
        encodeURIComponent(ig) +
        '&targetunit=' +
        encodeURIComponent(tu) +
        '&sourceunit=' +
        encodeURIComponent(mt) +
        '&sourceamount=' +
        fl
    );
  }

  fetchNutritionByDish(dish: string) {
    return this.http.get(
      NutroService.ENDPOINT + '/getnutri?name=' + encodeURIComponent(dish)
    );
  }

  fetchRecipeByCalories(calories: number) {
    return this.http.get(NutroService.ENDPOINT + '/resbycals/' + calories);
  }
}