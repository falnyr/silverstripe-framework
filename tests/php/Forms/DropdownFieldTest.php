<?php

namespace SilverStripe\Forms\Tests;

use SilverStripe\Control\Controller;
use SilverStripe\ORM\ArrayList;
use SilverStripe\Dev\CSSContentParser;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\RequiredFields;
use SilverStripe\Forms\FormTemplateHelper;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\Form;
use SilverStripe\View\ArrayData;
use SilverStripe\ORM\Map;

class DropdownFieldTest extends SapphireTest
{

    public function testGetSource()
    {
        $source = [1=>'one', 2 => 'two'];
        $field = new DropdownField('Field', null, $source);
        $this->assertEquals(
            $source,
            $field->getSource()
        );
        $this->assertEquals(
            $source,
            $field->getSource()
        );

        $items = new ArrayList(
            [
            [ 'ID' => 1, 'Title' => 'ichi', 'OtherField' => 'notone' ],
            [ 'ID' => 2, 'Title' => 'ni', 'OtherField' => 'nottwo' ],
            ]
        );
        $field->setSource($items);
        $this->assertEquals(
            $field->getSource(),
            [
                1 => 'ichi',
                2 => 'ni',
            ]
        );

        $map = new Map($items, 'ID', 'OtherField');
        $field->setSource($map);
        $this->assertEquals(
            $field->getSource(),
            [
                1 => 'notone',
                2 => 'nottwo',
            ]
        );
    }

    /**
     * Test different data sources
     */
    public function testSources()
    {
        // Array
        $items = ['a' => 'Apple', 'b' => 'Banana', 'c' => 'Cranberry'];
        $field = new DropdownField('Field', null, $items);
        $this->assertEquals($items, $field->getSource());

        // SS_List
        $list = new ArrayList(
            [
            new ArrayData(
                [
                'ID' => 'a',
                'Title' => 'Apple'
                ]
            ),
            new ArrayData(
                [
                'ID' => 'b',
                'Title' => 'Banana'
                ]
            ),
            new ArrayData(
                [
                'ID' => 'c',
                'Title' => 'Cranberry'
                ]
            )
            ]
        );
        $field2 = new DropdownField('Field', null, $list);
        $this->assertEquals($items, $field2->getSource());

        $field3 = new DropdownField('Field', null, $list->map());
        $this->assertEquals($items, $field3->getSource());
    }

    public function testReadonlyField()
    {
        $field = new DropdownField('FeelingOk', 'Are you feeling ok?', [0 => 'No', 1 => 'Yes']);
        $field->setEmptyString('(Select one)');
        $field->setValue(1);
        $readonlyField = $field->performReadonlyTransformation();
        preg_match('/Yes/', $field->Field() ?? '', $matches);
        $this->assertEquals($matches[0], 'Yes');
    }

    public function testHasEmptyDefault()
    {
        $source = [1 => 'one'];

        // Test getSource with empty
        $field = new DropdownField('Field', null, $source);
        $field->setHasEmptyDefault(true);

        $this->assertEquals(
            $field->getSource(),
            [
                1 => 'one'
            ]
        );

        // Test that an empty option comes through in the markup however
        $options = $this->findOptionElements($field->Field());

        $this->assertEquals(
            2,
            count($options ?? []),
            'Two options exist in the markup, one for the source, one for empty'
        );

        // the default value should be first
        $first = array_shift($options);
        $attrs = $first->attributes();

        $this->assertNotEquals(
            1,
            $attrs['value'],
            'First value is the not value (not the source value)'
        );

        // Test Field Without Empty
        $FieldWithoutEmpty = new DropdownField('Field', null, $source);
        $this->assertEquals(
            $FieldWithoutEmpty->getSource(),
            [
                1 => 'one'
            ]
        );

        // Test that an empty option does not comes through in the markup however
        $options = $this->findOptionElements($FieldWithoutEmpty->Field());

        $this->assertEquals(
            1,
            count($options ?? []),
            'As hasEmptyDefault is not provided, then no default option.'
        );
    }

    public function testEmpty()
    {
        $fieldName = 'TestField';
        $formName = 'testForm';
        // Create mock form
        $form = $this->createMock(Form::class);
        $form->method('getTemplateHelper')
            ->willReturn(FormTemplateHelper::singleton());

        $form->method('getHTMLID')
            ->willReturn($formName);

        $source = [
            'first' => 'value',
            0 => 'otherValue'
        ];
        $field = new DropdownField($fieldName, 'Test Field', $source);
        $field->setForm($form);

        $fieldId = $field->ID();
        $this->assertEquals($fieldId, sprintf('%s_%s', $formName, $fieldName));

        // Check state for default value
        $schemaStateDefaults = $field->getSchemaStateDefaults();
        $this->assertSame($fieldId, $schemaStateDefaults['id']);
        $this->assertSame($fieldName, $schemaStateDefaults['name']);
        $this->assertSame('first', $schemaStateDefaults['value']);

        // Check data for empty defaults
        $schemaDataDefaults = $field->getSchemaDataDefaults();
        $this->assertSame($fieldId, $schemaDataDefaults['id']);
        $this->assertSame($fieldName, $schemaDataDefaults['name']);
        $this->assertSame('text', $schemaDataDefaults['type']);
        $this->assertSame('SingleSelect', $schemaDataDefaults['schemaType']);
        $this->assertSame(sprintf('%s_Holder', $fieldId), $schemaDataDefaults['holderId']);
        $this->assertSame('Test Field', $schemaDataDefaults['title']);
        $this->assertSame('dropdown', $schemaDataDefaults['extraClass']);
        $this->assertSame(null, $schemaDataDefaults['data']['emptyString']);
        $this->assertSame(false, $schemaDataDefaults['data']['hasEmptyDefault']);

        // Set an empty string of field
        $field->setEmptyString('(Any)');

        // Check state for default value
        $schemaStateDefaults = $field->getSchemaStateDefaults();
        $this->assertSame($fieldId, $schemaStateDefaults['id']);
        $this->assertSame($fieldName, $schemaStateDefaults['name']);
        $this->assertSame('', $schemaStateDefaults['value']);

        // Check data for empty defaults
        $schemaDataDefaults = $field->getSchemaDataDefaults();
        $this->assertSame($fieldId, $schemaDataDefaults['id']);
        $this->assertSame($fieldName, $schemaDataDefaults['name']);
        $this->assertSame('text', $schemaDataDefaults['type']);
        $this->assertSame('SingleSelect', $schemaDataDefaults['schemaType']);
        $this->assertSame(sprintf('%s_Holder', $fieldId), $schemaDataDefaults['holderId']);
        $this->assertSame('Test Field', $schemaDataDefaults['title']);
        $this->assertSame('dropdown', $schemaDataDefaults['extraClass']);
        $this->assertSame('(Any)', $schemaDataDefaults['data']['emptyString']);
        $this->assertSame(true, $schemaDataDefaults['data']['hasEmptyDefault']);
    }

    public function testZeroArraySourceNotOverwrittenByEmptyString()
    {
        $source = [0=>'zero'];
        $field = new DropdownField('Field', null, $source);
        $field->setEmptyString('select...');
        $this->assertEquals(
            $field->getSource(),
            [
                0 => 'zero'
            ]
        );

        $options = $this->findOptionElements($field->Field());

        $this->assertEquals(
            2,
            count($options ?? []),
            'Two options exist in the markup, one for the source, one for empty'
        );
    }

    public function testStringZeroValueSelectedOptionBehaviour()
    {
        $field = new DropdownField(
            'Field',
            null,
            [
            '-1' => 'some negative',
            '0' => 'none',
            '1' => 'one',
            '2+' => 'two or more'
            ],
            '0'
        );

        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals((string) $selectedOptions[0], 'none', 'The selected option is "none"');

        $field = new DropdownField(
            'Field',
            null,
            [
            '-1' => 'some negative',
            '0' => 'none',
            '1' => 'one',
            '2+' => 'two or more'
            ],
            0
        );

        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals((string) $selectedOptions[0], 'none', 'The selected option is "none"');
    }

    public function testStringOneValueSelectedOptionBehaviour()
    {
        $field = new DropdownField(
            'Field',
            null,
            [
            '-1' => 'some negative',
            '0' => 'none',
            '1' => 'one',
            '2+' => 'two or more'
            ],
            '1'
        );


        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals((string) $selectedOptions[0], 'one', 'The selected option is "one"');

        $field = new DropdownField(
            'Field',
            null,
            [
            '-1' => 'some negative',
            '0' => 'none',
            '1' => 'one',
            '2+' => 'two or more'
            ],
            1
        );

        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals((string) $selectedOptions[0], 'one', 'The selected option is "one"');
    }

    public function testNumberOfSelectOptionsAvailable()
    {
        /* Create a field with a blank value */
        $field = $this->createDropdownField('(Any)');

        /* 3 options are available */
        $this->assertEquals(count($this->findOptionElements($field->Field()) ?? []), 3, '3 options are available');
        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals(
            count($selectedOptions ?? []),
            1,
            'We only have 1 selected option, since a dropdown can only possibly have one!'
        );

        /* Create a field without a blank value */
        $field = $this->createDropdownField();

        /* 2 options are available */
        $this->assertEquals(count($this->findOptionElements($field->Field()) ?? []), 2, '2 options are available');
        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals(count($selectedOptions ?? []), 0, 'There are no selected options');
    }

    public function testIntegerZeroValueSeelctedOptionBehaviour()
    {
        $field = $this->createDropdownField('(Any)', 0);
        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals((string) $selectedOptions[0], 'No', 'The selected option is "No"');
    }

    public function testBlankStringValueSelectedOptionBehaviour()
    {
        $field = $this->createDropdownField('(Any)');
        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals((string) $selectedOptions[0], '(Any)', 'The selected option is "(Any)"');
    }

    public function testNullValueSelectedOptionBehaviour()
    {
        $field = $this->createDropdownField('(Any)', null);
        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals((string) $selectedOptions[0], '(Any)', 'The selected option is "(Any)"');
    }

    public function testStringValueSelectedOptionBehaviour()
    {
        $field = $this->createDropdownField('(Any)', '1');
        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals((string) $selectedOptions[0], 'Yes', 'The selected option is "Yes"');
        $field->setSource(
            [
            'Cats' => 'Cats and Kittens',
            'Dogs' => 'Dogs and Puppies'
            ]
        );
        $field->setValue('Cats');
        $selectedOptions = $this->findSelectedOptionElements($field->Field());
        $this->assertEquals(
            (string) $selectedOptions[0],
            'Cats and Kittens',
            'The selected option is "Cats and Kittens"'
        );
    }

    public function testNumberOfDisabledOptions()
    {
        /* Create a field with a blank value & set 0 & 1 to disabled */
        $field = $this->createDropdownField('(Any)');
        $field->setDisabledItems([0,1]);

        /* 3 options are available */
        $this->assertEquals(count($this->findOptionElements($field->Field()) ?? []), 3, '3 options are available');

        /* There are 2 disabled options */
        $disabledOptions = $this->findDisabledOptionElements($field->Field());
        $this->assertEquals(count($disabledOptions ?? []), 2, 'We have 2 disabled options');

        /* Create a field without a blank value & set 1 to disabled, then set none to disabled (unset) */
        $field = $this->createDropdownField();
        $field->setDisabledItems([1]);

        /* 2 options are available */
        $this->assertEquals(count($this->findOptionElements($field->Field()) ?? []), 2, '2 options are available');

        /* get disabled items returns an array of one */
        $this->assertEquals(
            $field->getDisabledItems(),
            [ 1 ]
        );

        /* unset disabled items */
        $field->setDisabledItems([]);

        /* There are no disabled options anymore */
        $disabledOptions = $this->findDisabledOptionElements($field->Field());
        $this->assertEquals(count($disabledOptions ?? []), 0, 'There are no disabled options');
    }

    /**
     * The Field() method should be able to handle arrays as values in an edge case. If it couldn't handle it then
     * this test would trigger an array to string conversion PHP notice
     *
     * @dataProvider arrayValueProvider
     */
    public function testDropdownWithArrayValues($value)
    {
        $field = $this->createDropdownField();
        $field->setValue($value);
        $this->assertInstanceOf('SilverStripe\\ORM\\FieldType\\DBHTMLText', $field->Field());
        $this->assertSame($value, $field->Value());
    }

    /**
     * @return array
     */
    public function arrayValueProvider()
    {
        return [
            [[]],
            [[0]],
            [[123]],
            [['string']],
            ['Regression-ish test.']
        ];
    }

    /**
     * Create a test dropdown field, with the option to
     * set what source and blank value it should contain
     * as optional parameters.
     *
     * @param  string|null    $emptyString The text to display for the empty value
     * @param  string|integer $value       The default value of the field
     * @return DropdownField object
     */
    public function createDropdownField($emptyString = null, $value = '')
    {
        /* Set up source, with 0 and 1 integers as the values */
        $source = [
            0 => 'No',
            1 => 'Yes'
        ];

        $field = new DropdownField('Field', null, $source, $value);

        if ($emptyString !== null) {
            $field->setEmptyString($emptyString);
        }

        return $field;
    }

    /**
     * Find all the <OPTION> elements from a
     * string of HTML.
     *
     * @param  string $html HTML to scan for elements
     * @return SimpleXMLElement
     */
    public function findOptionElements($html)
    {
        $parser = new CSSContentParser($html);
        return $parser->getBySelector('option');
    }

    /**
     * Find all the <OPTION> elements from a
     * string of HTML that have the "selected"
     * attribute.
     *
     * @param  string $html HTML to parse for elements
     * @return array of SimpleXMLElement objects
     */
    public function findSelectedOptionElements($html)
    {
        $options = $this->findOptionElements($html);

        /* Find any elements that have the "selected" attribute and put them into a list */
        $foundSelected = [];
        foreach ($options as $option) {
            $attributes = $option->attributes();
            if ($attributes) {
                foreach ($attributes as $attribute => $value) {
                    if ($attribute == 'selected') {
                        $foundSelected[] = $option;
                    }
                }
            }
        }

        return $foundSelected;
    }

    /**
     * Find all the <OPTION> elements from a
     * string of HTML that have the "disabled"
     * attribute.
     *
     * @param  string $html HTML to parse for elements
     * @return array of SimpleXMLElement objects
     */
    public function findDisabledOptionElements($html)
    {
        $options = $this->findOptionElements($html);

        /* Find any elements that have the "disabled" attribute and put them into a list */
        $foundDisabled = [];
        foreach ($options as $option) {
            $attributes = $option->attributes();
            if ($attributes) {
                foreach ($attributes as $attribute => $value) {
                    if ($attribute == 'disabled') {
                        $foundDisabled[] = $option;
                    }
                }
            }
        }

        return $foundDisabled;
    }

    public function testValidation()
    {
        $field = DropdownField::create(
            'Test',
            'Testing',
            [
            "One" => "One",
            "Two" => "Two",
            "Five" => "Five"
            ]
        );
        $validator = new RequiredFields();
        new Form(null, 'Form', new FieldList($field), new FieldList(), $validator);
        $field->setValue("One");
        $this->assertTrue($field->validate($validator));
        $field->setName("TestNew"); //try changing name of field
        $this->assertTrue($field->validate($validator));
        //non-existent value should make the field invalid
        $field->setValue("Three");
        $this->assertFalse($field->validate($validator));
        //empty string shouldn't validate
        $field->setValue('');
        $this->assertFalse($field->validate($validator));
        //empty field should validate after being set
        $field->setEmptyString('Empty String');
        $field->setValue('');
        $this->assertTrue($field->validate($validator));
        //disabled items shouldn't validate
        $field->setDisabledItems(['Five']);
        $field->setValue('Five');
        $this->assertFalse($field->validate($validator));
    }

    /**
     * #2939 DropdownField creates invalid HTML when required
     */
    public function testRequiredDropdownHasEmptyDefault()
    {
        $field = new DropdownField("RequiredField", "dropdown", ["item 1", "item 2"]);

        $form = new Form(
            Controller::curr(),
            "form",
            new FieldList($field),
            new FieldList(),
            new RequiredFields(["RequiredField"])
        );

        $this->assertTrue($field->getHasEmptyDefault());
    }

    public function testEmptySourceDoesntBlockValidation()
    {
        // Empty source
        $field = new DropdownField("EmptySource", "", []);
        $v = new RequiredFields();
        $field->validate($v);
        $this->assertTrue($v->getResult()->isValid());

        // Source with a setEmptyString
        $field = new DropdownField("EmptySource", "", []);
        $field->setEmptyString('(Select one)');
        $v = new RequiredFields();
        $field->validate($v);
        $this->assertTrue($v->getResult()->isValid());

        // Source with an empty value
        $field = new DropdownField("SourceWithBlankVal", "", [ "" => "(Choose)" ]);
        $v = new RequiredFields();
        $field->validate($v);
        $this->assertTrue($v->getResult()->isValid());

        // Source with all items disabled
        $field = new DropdownField("SourceWithBlankVal", "", [ "A" => "A", "B" => "B" ]);
        $field->setDisabledItems([ 'A', 'B' ]);
        $v = new RequiredFields();
        $field->validate($v);
        $this->assertTrue($v->getResult()->isValid());
    }

    public function provideGetDefaultValue(): array
    {
        return [
            [
                'value' => null,
                'hasEmptyDefault' => true,
                'expected' => '',
            ],
            [
                'value' => null,
                'hasEmptyDefault' => false,
                'expected' => 'one',
            ],
            [
                'value' => 'four',
                'hasEmptyDefault' => true,
                'expected' => '',
            ],
            [
                'value' => 'four',
                'hasEmptyDefault' => false,
                'expected' => 'one',
            ],
            [
                'value' => 'two',
                'hasEmptyDefault' => true,
                'expected' => 'two',
            ],
            [
                'value' => 'two',
                'hasEmptyDefault' => false,
                'expected' => 'two',
            ],
            [
                // Note this is an int, but matches against the string key
                'value' => 3,
                'hasEmptyDefault' => true,
                'expected' => 3,
            ],
            [
                'value' => 3,
                'hasEmptyDefault' => false,
                'expected' => 3,
            ],
        ];
    }

    /**
     * @dataProvider provideGetDefaultValue
     */
    public function testGetDefaultValue(mixed $value, bool $hasEmptyDefault, mixed $expected): void
    {
        $field = new DropdownField('MyField', source: ['one' => 'one', 'two' => 'two', '3' => 'three']);
        $field->setHasEmptyDefault($hasEmptyDefault);
        $field->setValue($value);
        $this->assertSame($expected, $field->getDefaultValue());
    }
}
