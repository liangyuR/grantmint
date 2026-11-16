export const beijingTime = (value: string) => new Date(value).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hourCycle: 'h23' });
export const stopDate = (value: string) => new Date(`${value}T00:00:00+08:00`).toISOString();
export const warningTime = (value: string) => beijingTime(new Date(new Date(value).getTime() - 7 * 86400000).toISOString());
export const deliveryLabels = { not_activated: '待激活', pending: '待领取 / 尚未确认', confirmed: '设备已确认' };
