export type IOCType = 'IP' | 'Domain' | 'Hash' | 'Email';

export type IOC = {
  id: string;
  value: string;
  type: IOCType;
  threatFamily: string;
  confidence: number;
  source: string;
  enabled: boolean;
  createdAt: string;
};

export type IOCMatch = {
  ioc: IOC;
  triggerTimestamp: string;
};
