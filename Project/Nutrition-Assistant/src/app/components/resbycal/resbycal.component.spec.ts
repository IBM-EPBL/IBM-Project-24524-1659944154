import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ResbycalComponent } from './resbycal.component';

describe('ResbycalComponent', () => {
  let component: ResbycalComponent;
  let fixture: ComponentFixture<ResbycalComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ ResbycalComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(ResbycalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
