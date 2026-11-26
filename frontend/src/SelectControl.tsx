import * as Select from '@radix-ui/react-select';
import { Check, ChevronDown, ChevronUp } from 'lucide-react';

export function SelectControl({ label, value, onChange, options, disabled }: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  disabled?: boolean;
}) {
  return <Select.Root value={'option:' + value} onValueChange={(next) => onChange(next.slice(7))} disabled={disabled}>
    <Select.Trigger aria-label={label} className="select-trigger">
      <Select.Value /><Select.Icon asChild><ChevronDown size={14} /></Select.Icon>
    </Select.Trigger>
    <Select.Portal>
      <Select.Content className="select-content" position="popper" sideOffset={5} collisionPadding={8}>
        <Select.ScrollUpButton className="select-scroll"><ChevronUp size={14} /></Select.ScrollUpButton>
        <Select.Viewport>
          {options.map((option) => <Select.Item key={option.value} value={'option:' + option.value} className="select-option">
            <Select.ItemText>{option.label}</Select.ItemText>
            <Select.ItemIndicator><Check size={14} /></Select.ItemIndicator>
          </Select.Item>)}
        </Select.Viewport>
        <Select.ScrollDownButton className="select-scroll"><ChevronDown size={14} /></Select.ScrollDownButton>
      </Select.Content>
    </Select.Portal>
  </Select.Root>;
}
