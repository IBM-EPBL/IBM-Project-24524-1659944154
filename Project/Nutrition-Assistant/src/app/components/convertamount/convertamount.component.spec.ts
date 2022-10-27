import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ConvertamountComponent } from './convertamount.component';

describe('ConvertamountComponent', () => {
  let component: ConvertamountComponent;
  let fixture: ComponentFixture<ConvertamountComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ ConvertamountComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(ConvertamountComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
