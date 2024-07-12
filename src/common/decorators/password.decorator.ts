import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

export function ConfirmPassword(property: string, validationOptions?: ValidationOptions) {
  return (object: any, propertyName: string) => {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: validationOptions,
      constraints: [property],
      validator: ConfirmPasswordConstraints,
    });
  };
}

@ValidatorConstraint({
  name: 'confirmPassword',
  async: false,
})
export class ConfirmPasswordConstraints implements ValidatorConstraintInterface {
  validate(value: any, args: ValidationArguments) {
    const { object, constraints } = args;
    const [property] = constraints;
    const relatedValue = object[property];
    return value === relatedValue;
  }

  defaultMessage(args: ValidationArguments): string {
    return 'password and confirm password should be equals';
  }
}
