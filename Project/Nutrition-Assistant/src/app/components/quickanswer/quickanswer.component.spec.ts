import { ComponentFixture, TestBed } from '@angular/core/testing';

import { QuickanswerComponent } from './quickanswer.component';

describe('QuickanswerComponent', () => {
  let component: QuickanswerComponent;
  let fixture: ComponentFixture<QuickanswerComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ QuickanswerComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(QuickanswerComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
