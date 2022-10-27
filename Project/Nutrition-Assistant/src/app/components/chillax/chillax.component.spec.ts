import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ChillaxComponent } from './chillax.component';

describe('ChillaxComponent', () => {
  let component: ChillaxComponent;
  let fixture: ComponentFixture<ChillaxComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ ChillaxComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(ChillaxComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
