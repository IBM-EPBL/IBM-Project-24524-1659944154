import { TestBed } from '@angular/core/testing';

import { NutroService } from './nutro.service';

describe('NutroService', () => {
  let service: NutroService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(NutroService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
