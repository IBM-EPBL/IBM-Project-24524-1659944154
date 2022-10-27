import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NutbydishComponent } from './nutbydish.component';

describe('NutbydishComponent', () => {
  let component: NutbydishComponent;
  let fixture: ComponentFixture<NutbydishComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ NutbydishComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(NutbydishComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
