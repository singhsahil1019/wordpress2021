(function () {
  'use strict';
  /**
   * Defines the Hustle Object
   *
   * @type {{define, getModules, get, modules}}
   */

  window.Hustle = function ($, doc, win) {
    var currentModules = {},
        _modules = {},
        _TemplateOptions = {
      evaluate: /<#([\s\S]+?)#>/g,
      interpolate: /\{\{\{([\s\S]+?)\}\}\}/g,
      escape: /\{\{([^\}]+?)\}\}(?!\})/g
    };

    var define = function define(moduleName, module) {
      var splits = moduleName.split('.');

      if (splits.length) {
        // if module_name has more than one object name, then add the module definition recursively
        var recursive = function recursive(incomingModuleName, modules) {
          var arr = incomingModuleName.split('.'),
              _moduleName = arr.splice(0, 1)[0];
          var invoked;

          if (!_moduleName) {
            return;
          }

          if (!arr.length) {
            invoked = module.call(null, $, doc, win);
            modules[_moduleName] = _.isFunction(invoked) || 'undefined' === typeof invoked ? invoked : _.extend(modules[_moduleName] || {}, invoked);
          } else {
            modules[_moduleName] = modules[_moduleName] || {};
          }

          if (arr.length && _moduleName) {
            recursive(arr.join('.'), modules[_moduleName]);
          }
        };

        recursive(moduleName, _modules);
      } else {
        var m = _modules[moduleName] || {};
        _modules[moduleName] = _.extend(m, module.call(null, $, doc, win));
      }
    },
        get = function get(moduleName) {
      var module, _recursive;

      if (moduleName.split('.').length) {
        // recursively fetch the module
        module = false;

        _recursive = function recursive(incomingModuleName, modules) {
          var arr = incomingModuleName.split('.'),
              _moduleName = arr.splice(0, 1)[0];
          module = modules[_moduleName];

          if (arr.length) {
            _recursive(arr.join('.'), modules[_moduleName]);
          }
        };

        _recursive(moduleName, _modules);

        return module;
      }

      return _modules[moduleName] || false;
    },
        Events = _.extend({}, Backbone.Events),
        View = Backbone.View.extend({
      initialize: function initialize() {
        if (_.isFunction(this.initMix)) {
          this.initMix.apply(this, arguments);
        }

        if (this.render) {
          this.render = _.wrap(this.render, function (render) {
            this.trigger('before_render');
            render.call(this);
            Events.trigger('view.rendered', this);
            this.trigger('rendered');
          });
        }

        if (_.isFunction(this.init)) {
          this.init.apply(this, arguments);
        }
      }
    }),
        template = _.memoize(function (id) {
      var compiled;
      return function (data) {
        compiled = compiled || _.template(document.getElementById(id).innerHTML, null, _TemplateOptions);
        return compiled(data).replace('/*<![CDATA[*/', '').replace('/*]]>*/', '');
      };
    }),
        createTemplate = _.memoize(function (str) {
      var cache;
      return function (data) {
        cache = cache || _.template(str, null, _TemplateOptions);
        return cache(data);
      };
    }),
        getTemplateOptions = function getTemplateOptions() {
      return $.extend(true, {}, _TemplateOptions);
    },
        setModule = function setModule(moduleId, moduleView) {
      currentModules[moduleId] = moduleView;
    },
        getModules = function getModules() {
      return currentModules;
    },
        getModule = function getModule(moduleId) {
      return currentModules[moduleId];
    },
        consts = function () {
      return {
        ModuleShowCount: 'hustle_module_show_count-'
      };
    }();

    return {
      define: define,
      setModule: setModule,
      getModules: getModules,
      getModule: getModule,
      get: get,
      Events: Events,
      View: View,
      template: template,
      createTemplate: createTemplate,
      getTemplateOptions: getTemplateOptions,
      consts: consts
    };
  }(jQuery, document, window);
})(jQuery);
var Optin = window.Optin || {};
Optin.Models = {};

(function ($) {
  'use strict';

  Optin.NEVER_SEE_PREFIX = 'inc_optin_never_see_again-';
  Optin.COOKIE_PREFIX = 'inc_optin_long_hidden-';
  Optin.POPUP_COOKIE_PREFIX = 'inc_optin_popup_long_hidden-';
  Optin.SLIDE_IN_COOKIE_PREFIX = 'inc_optin_slide_in_long_hidden-';
  Optin.EMBEDDED_COOKIE_PREFIX = 'inc_optin_embedded_long_hidden-';
  Optin.template = _.memoize(function (id) {
    var compiled;
    var options = {
      evaluate: /<#([\s\S]+?)#>/g,
      interpolate: /\{\{\{([\s\S]+?)\}\}\}/g,
      escape: /\{\{([^\}]+?)\}\}(?!\})/g
    };
    return function (data) {
      compiled = compiled || _.template($('#' + id).html(), null, options);
      return compiled(data).replace('/*<![CDATA[*/', '').replace('/*]]>*/', '');
    };
  });
  /**
   * Compatibility with other plugin/theme e.g. upfront
   *
   */

  Optin.templateCompat = _.memoize(function (id) {
    var compiled;
    return function (data) {
      compiled = compiled || _.template($('#' + id).html());
      return compiled(data).replace('/*<![CDATA[*/', '').replace('/*]]>*/', '');
    };
  });
  Optin.cookie = {
    // Get a cookie value.
    get: function get(name) {
      var c;
      var cookiesArray = document.cookie.split(';'),
          cookiesArrayLength = cookiesArray.length,
          cookieName = name + '=';

      for (var i = 0; i < cookiesArrayLength; i += 1) {
        c = cookiesArray[i];

        while (' ' === c.charAt(0)) {
          c = c.substring(1, c.length);
        }

        if (0 === c.indexOf(cookieName)) {
          var _val = c.substring(cookieName.length, c.length);

          return _val ? JSON.parse(_val) : _val;
        }
      }

      return null;
    },
    // Saves the value into a cookie.
    set: function set(name, value, days) {
      var date, expires;
      value = Array.isArray(value) || $.isPlainObject(value) ? JSON.stringify(value) : value;

      if (!isNaN(days)) {
        date = new Date();
        date.setTime(date.getTime() + days * 24 * 60 * 60 * 1000);
        expires = '; expires=' + date.toGMTString();
      } else {
        expires = '';
      }

      document.cookie = name + '=' + value + expires + '; path=/';
    }
  };
  Optin.Mixins = {
    _mixins: {},
    _servicesMixins: {},
    _desingMixins: {},
    _displayMixins: {},
    add: function add(id, obj) {
      this._mixins[id] = obj;
    },
    getMixins: function getMixins() {
      return this._mixins;
    },
    addServicesMixin: function addServicesMixin(id, obj) {
      this._servicesMixins[id] = obj;
    },
    getServicesMixins: function getServicesMixins() {
      return this._servicesMixins;
    }
  };
})(jQuery);
(function ($) {
  'use strict';

  Hustle.Events.on('view.rendered', function (view) {
    if (view instanceof Backbone.View) {
      var accessibleHide = function accessibleHide($elements) {
        $elements.hide();
        $elements.prop('tabindex', '-1');
        $elements.prop('hidden', true);
      },
          accessibleShow = function accessibleShow($elements) {
        $elements.show();
        $elements.prop('tabindex', '0');
        $elements.removeProp('hidden');
      }; // Init tabs (new markup)


      SUI.tabs({
        callback: function callback(tab, panel) {
          // eslint-disable-line no-unused-vars
          var wrapper = tab.closest('.sui-tabs'); // Handlers for "CTA Helper Text" options.

          var ctaHelperEnable = 'cta-helper-enable',
              ctaHelperDisable = 'cta-helper-disable';

          if ('tab-' + ctaHelperEnable === tab.attr('id')) {
            wrapper.find('#input-' + ctaHelperEnable).click();
          } else if ('tab-' + ctaHelperDisable === tab.attr('id')) {
            wrapper.find('#input-' + ctaHelperDisable).click();
          } // Handlers for "Set Schedule" modal.


          var scheduleEveryday = 'schedule-everyday',
              scheduleSomedays = 'schedule-somedays',
              scheduleServer = 'timezone-server',
              scheduleCustom = 'timezone-custom';

          if ('tab-' + scheduleEveryday === tab.attr('id')) {
            wrapper.find('#input-' + scheduleEveryday).click();
          }

          if ('tab-' + scheduleSomedays === tab.attr('id')) {
            wrapper.find('#input-' + scheduleSomedays).click();
          }

          if ('tab-' + scheduleServer === tab.attr('id')) {
            wrapper.find('#input-' + scheduleServer).click();
          }

          if ('tab-' + scheduleCustom === tab.attr('id')) {
            wrapper.find('#input-' + scheduleCustom).click();
          }
        }
      });
      /**
       * Hides and shows the content of the settings using sui-side-tabs.
       * For us, non-designers: sui-side-tabs are the "buttons" that work as labels for radio inputs.
       *
       * @todo TO BE REMOVED.
       * @since 4.0.0
       * @since 4.3.0 Handle added for tabs using buttons instead of inputs.
       */

      view.$('.sui-side-tabs').each(function () {
        var $this = $(this); // Show or hide dependent content based on the selected settings.
        // Only working for old tabs not using buttons but inputs.

        var $inputs = $this.find('.sui-tabs-menu .sui-tab-item input');

        if (!$inputs.length) {
          return;
        }

        var handleTabs = function handleTabs() {
          // This holds the dependency name of the selected input.
          // It's used to avoid hiding a container that should be shown
          // when two or more tabs share the same container.
          var shownDep = '';
          $.each($inputs, function () {
            var $input = $(this),
                $label = $input.parent('label'),
                dependencyName = $input.data('tab-menu'),
                $tabContent = $(".sui-tabs-content [data-tab-content=\"".concat(dependencyName, "\"]")),
                $tabDependent = $("[data-tab-dependent=\"".concat(dependencyName, "\"]"));

            if ($input[0].checked) {
              $label.addClass('active');

              if (dependencyName) {
                shownDep = dependencyName;
                $tabContent.addClass('active');
                accessibleShow($tabDependent);
              }
            } else {
              $label.removeClass('active');

              if (dependencyName !== shownDep) {
                $tabContent.removeClass('active');
                accessibleHide($tabDependent);
              }
            }
          });
        }; // Do it on load.


        handleTabs(); // And do it on change.

        $inputs.on('change', function () {
          return handleTabs();
        }); // Probably to be handled by SUI in the future.
        // Handle new tabs using buttons instead of radios and labels.

        var $buttons = $this.find('button.sui-tab-item');
        $buttons.on('click', function () {
          var $button = $(this),
              $buttonRadio = $('#' + $button.data('label-for'));

          if ($buttonRadio.length) {
            $buttonRadio.trigger('click').trigger('change');
          }
        }); // Make buttons selected on load.

        var $selected = $this.children('.hustle-tabs-option:checked');

        if ($selected.length) {
          var id = $selected.prop('id'),
              $button = $this.find("button[data-label-for=\"".concat(id, "\"]"));
          $button.trigger('click');
        }
      }); // Same as the one above but for the tabs markup in the new component files.

      view.$('.sui-side-tabs').each(function () {
        var $sideTabsContainer = $(this); // Show or hide dependent content based on the selected settings.

        var $inputs = $sideTabsContainer.children('.hustle-tabs-option');

        if (!$inputs.length) {
          return;
        }

        var handleTabs = function handleTabs() {
          // Used to avoid hiding a container that should be shown
          // when two or more tabs share the same container.
          var shownDep = '';
          $.each($inputs, function () {
            var $input = $(this),
                inputId = $input.attr('id'),
                $button = $sideTabsContainer.find("button[data-label-for=\"".concat(inputId, "\"]")),
                dependencyId = $button.attr('aria-controls'),
                //// Use this instead in 4.4 with new multiple-triggers in place. $tabDependent = $( `#${ dependencyId }` );
            $tabDependent = $("div[id=\"".concat(dependencyId, "\"]"));

            if ($input[0].checked) {
              $button.addClass('active');

              if (dependencyId) {
                shownDep = dependencyId;
                accessibleShow($tabDependent);
              }
            } else {
              $button.removeClass('active');

              if (dependencyId !== shownDep) {
                accessibleHide($tabDependent);
              }
            }
          });
        }; // Do it on load.


        handleTabs(); // And do it on change.

        $inputs.on('change', function () {
          return handleTabs();
        });
        var $buttons = $sideTabsContainer.children('.sui-tabs-menu').find('button.sui-tab-item');
        $buttons.on('click', function () {
          var $button = $(this),
              // Use this instead in 4.4 with new multiple-triggers in place. $( '#' + $button.data( 'label-for' ) );
          $buttonRadio = $('input[id="' + $button.data('label-for') + '"]');

          if ($buttonRadio.length) {
            $buttonRadio.trigger('click').trigger('change');
          }
        });
      });
      view.$('.select-content-switcher-wrapper').each(function () {
        var $this = $(this),
            $select = $this.find('.select-content-switcher'),
            $options = $select.find('option'),
            switchContent = function switchContent() {
          var $selected = $select.find(':selected'),
              dependencyName = $selected.data('switcher-menu'),
              $selectedTabContent = $this.find(".select-switcher-content[data-switcher-content=\"".concat(dependencyName, "\"]"));
          $.each($options, function () {
            var $option = $(this);

            if ($option.data('switcher-menu') === dependencyName) {
              accessibleShow($selectedTabContent);
            } else {
              var $tabContent = $this.find(".select-switcher-content[data-switcher-content=\"".concat($option.data('switcher-menu'), "\"]"));
              accessibleHide($tabContent);
            }
          });
        }; // Do it on load.


        switchContent(); // And do it on change.

        $select.on('change', function () {
          return switchContent();
        });
      });
      /**
       * Hides and shows the container dependent on toggles
       * on view load and on change.
       * Used in wizards and global settings page.
       *
       * @since 4.0.3
       */

      view.$('.hustle-toggle-with-container').each(function () {
        var $this = $(this),
            $checkbox = $this.find('input[type=checkbox]'),
            $containersOn = $("[data-toggle-content=\"".concat($this.data('toggle-on'), "\"]")),
            $containersOff = $("[data-toggle-content=\"".concat($this.data('toggle-off'), "\"]")),
            doToggle = function doToggle() {
          if ($checkbox[0].checked) {
            Module.Utils.accessibleShow($containersOn);
            Module.Utils.accessibleHide($containersOff);
          } else {
            Module.Utils.accessibleShow($containersOff);
            Module.Utils.accessibleHide($containersOn);
          }
        }; // Do it on load.


        doToggle(); // And do it on change.

        $checkbox.on('change', doToggle);
      });
      /**
       * Toggles the 'disabled' property from the field dependent to a radio
       * based on the selected value.
       * Used in wizards.
       *
       * @since 4.3.0
       */

      view.$('.hustle-radio-with-dependency-to-disable').each(function () {
        var $radio = $(this),
            relationName = $radio.data('disable'),
            $dependentField = $("[data-disable-content=\"".concat(relationName, "\"]")),
            disableOff = $dependentField.data('disable-off'),
            disableOn = $dependentField.data('disable-on');

        var toggleDisabled = function toggleDisabled() {
          if (!$radio.is(':checked')) {
            return;
          }

          if (disableOff) {
            if (disableOff === $radio.val()) {
              $dependentField.prop('disabled', false);
            } else {
              $dependentField.prop('disabled', true);
            }

            return;
          }

          if (disableOn) {
            if (disableOn === $radio.val()) {
              $dependentField.prop('disabled', true);
            } else {
              $dependentField.prop('disabled', false);
            }
          }
        };

        toggleDisabled();
        $radio.on('change', toggleDisabled);
      });
      /**
       * Toggles the 'disabled' property from the field dependent to a select
       * based on the selected value.
       * Used in wizards.
       *
       * @since 4.3.0
       */

      view.$('.hustle-select-with-dependency-to-disable').each(function () {
        var $select = $(this),
            relationName = $select.data('disable'),
            $dependentField = $("[data-disable-content=\"".concat(relationName, "\"]")),
            disableOff = $dependentField.data('disable-off'),
            disableOn = $dependentField.data('disable-on');

        var toggleDisabled = function toggleDisabled() {
          if (disableOff) {
            if (disableOff === $select.val()) {
              $dependentField.prop('disabled', false);
            } else {
              $dependentField.prop('disabled', true);
            }

            return;
          }

          if (disableOn) {
            if (disableOn === $select.val()) {
              $dependentField.prop('disabled', true);
            } else {
              $dependentField.prop('disabled', false);
            }
          }
        };

        toggleDisabled();
        $select.on('change', toggleDisabled);
      });
      Module.Utils.showHideDependencyOnSelectChange(view.$el);
    }
  }); // TODO: probably move this to the view where it's actually used.

  $(document).ready(function () {
    // Delete module
    $('.hustle-delete-module-button').on('click', function (e) {
      e.preventDefault();
      var $this = $(e.currentTarget),
          data = {
        id: $this.data('id'),
        nonce: $this.data('nonce'),
        action: 'delete',
        title: $this.data('title'),
        description: $this.data('description'),
        actionClass: 'hustle-single-module-button-action'
      };
      Module.deleteModal.open(data, $this[0]);
    });
    /**
     * The "are you sure?" modal from before resetting the tracking data of modules.
     *
     * @since 4.0.0
     * @param {Event} e Event.
     */

    $('.hustle-module-tracking-reset-button').on('click', function (e) {
      e.preventDefault();
      var $this = $(e.target),
          data = {
        id: $this.data('module-id'),
        nonce: optinVars.single_module_action_nonce,
        action: 'reset-tracking',
        title: $this.data('title'),
        description: $this.data('description'),
        actionClass: 'hustle-single-module-button-action'
      };
      Module.deleteModal.open(data, $this[0]);
    }); // Makes the 'copy' button work.

    $('.hustle-copy-shortcode-button').on('click', function (e) {
      e.preventDefault();
      var $button = $(e.target),
          shortcode = $button.data('shortcode'),
          $inputWrapper = $button.closest('.sui-with-button-inside');

      if ('undefined' !== typeof shortcode) {
        // Actions in listing pages.
        var $temp = $('<input />');
        $('body').append($temp);
        $temp.val(shortcode).trigger('select');
        document.execCommand('copy');
        $temp.remove();
        Module.Notification.open('success', optinVars.messages.shortcode_copied);
      } else if ($inputWrapper.length) {
        // Copy shortcode in wizard pages.
        var $inputWithCopy = $inputWrapper.find('input[type="text"]');
        $inputWithCopy.trigger('select');
        document.execCommand('copy');
      }
    }); // Dismiss for all the notices using the template from Hustle_Notifications::show_notice().

    $('.hustle-dismissible-admin-notice .notice-dismiss, .hustle-dismissible-admin-notice .dismiss-notice').on('click', function (e) {
      e.preventDefault();
      var $container = $(e.currentTarget).closest('.hustle-dismissible-admin-notice');
      $.post(ajaxurl, {
        action: 'hustle_dismiss_notification',
        name: $container.data('name'),
        _ajax_nonce: optinVars.dismiss_notice_nonce
      }).always($container.fadeOut());
    }); // Opens the confirmation modal for dismissing the tracking migration notice.

    $('#hustle-tracking-migration-notice .hustle-notice-dismiss').on('click', function (e) {
      e.preventDefault();
      $('#hustle-dismiss-modal-button').on('click', function (ev) {
        ev.preventDefault();
        $.post(ajaxurl, {
          action: 'hustle_dismiss_notification',
          name: $(ev.currentTarget).data('name'),
          _ajax_nonce: $(ev.currentTarget).data('nonce')
        }).always(function () {
          return location.reload();
        });
      });
      SUI.openModal('hustle-dialog--migrate-dismiss-confirmation', $('.sui-header-title'));
    });

    if ($('.sui-form-field input[type=number]').length) {
      $('.sui-form-field input[type=number]').on('keydown', function (e) {
        if ($(this)[0].hasAttribute('min') && 0 <= $(this).attr('min')) {
          var char = e.originalEvent.key.replace(/[^0-9^.^,]/, '');

          if (0 === char.length && !(e.originalEvent.ctrlKey || e.originalEvent.metaKey)) {
            e.preventDefault();
          }
        }
      });
    }

    setTimeout(function () {
      if ($('.hustle-scroll-to').length) {
        $('html, body').animate({
          scrollTop: $('.hustle-scroll-to').offset().top
        }, 'slow');
      }
    }, 100); //table checkboxes

    $('.hustle-check-all').on('click', function (e) {
      var $this = $(e.target),
          $list = $this.parents('.sui-wrap-hustle').find('.hustle-list'),
          allChecked = $this.is(':checked');
      $list.find('.hustle-listing-checkbox').prop('checked', allChecked);
      $this.parents('.sui-wrap-hustle').find('.hustle-check-all').prop('checked', allChecked);
      $('.hustle-bulk-apply-button').prop('disabled', !allChecked);
    });
    $('.hustle-list .hustle-listing-checkbox').on('click', function (e) {
      var $this = $(e.target),
          $list = $this.parents('.sui-wrap-hustle').find('.hustle-list'),
          allChecked = $this.is(':checked') && !$list.find('.hustle-listing-checkbox:not(:checked)').length,
          count = $list.find('.hustle-listing-checkbox:checked').length,
          disabled = 0 === count;
      $('.hustle-check-all').prop('checked', allChecked);
      $('.hustle-bulk-apply-button').prop('disabled', disabled);
    });
    $('.hustle-bulk-apply-button').on('click', function (e) {
      var $this = $(e.target),
          value = $('select option:selected', $this.closest('.hui-bulk-actions')).val(),
          elements = $('.hustle-list .hustle-listing-checkbox:checked');

      if (0 === elements.length || 'undefined' === value) {
        return false;
      }

      var ids = [];
      $.each(elements, function () {
        ids.push($(this).val());
      });

      if ('delete-all' === value) {
        var data = {
          ids: ids.join(','),
          nonce: $this.siblings('input[name="hustle_nonce"]').val(),
          title: $this.data('title'),
          description: $this.data('description'),
          action: value
        };
        Module.deleteModal.open(data, $this[0]);
        return false;
      }
    });
  });
})(jQuery);
Hustle.define('Modals.Migration', function ($) {
  'use strict';

  var migrationModalView = Backbone.View.extend({
    el: '#hustle-dialog--migrate',
    data: {},
    events: {
      'click #hustle-migrate-start': 'migrateStart',
      'click #hustle-create-new-module': 'createModule',
      'click .sui-box-selector': 'enableContinue',
      'click .hustle-dialog-migrate-skip': 'dismissModal'
    },
    initialize: function initialize() {
      if (!this.$el.length) {
        return;
      }

      var currentSlide = '',
          focusOnOpen = '';

      if (0 === this.$el.data('isFirst')) {
        currentSlide = '#hustle-dialog--migrate-slide-2';
        focusOnOpen = 'hustle-migrate-start';
      } else {
        currentSlide = '#hustle-dialog--migrate-slide-1';
        focusOnOpen = 'hustle-migrate-get-started';
      }

      this.$(currentSlide).addClass('sui-active sui-loaded');
      setTimeout(function () {
        return SUI.openModal('hustle-dialog--migrate', focusOnOpen, $('.sui-wrap-hustle')[0], false);
      }, 100);
      this.$progressBar = this.$el.find('.sui-progress .sui-progress-bar span');
      this.$progressText = this.$el.find('.sui-progress .sui-progress-text span');
      this.$partialRows = this.$el.find('#hustle-partial-rows');
    },
    migrateStart: function migrateStart(e) {
      var me = this;
      var button = $(e.target);
      var $container = this.$el,
          $dialog = $container.find('#hustle-dialog--migrate-slide-2'),
          $description = $dialog.find('#hustle-dialog--migrate-slide-2-description'); // On load button

      button.addClass('sui-button-onload'); // Remove skip migration link

      $dialog.find('.hustle-dialog-migrate-skip').remove();
      $description.text($description.data('migrate-text'));
      Module.Utils.accessibleHide($dialog.find('div[data-migrate-start]'));
      Module.Utils.accessibleHide($dialog.find('div[data-migrate-failed]'));
      Module.Utils.accessibleShow($dialog.find('div[data-migrate-progress]'));
      SUI.closeNotice('hustle-dialog--migrate-error-notice');
      me.migrateTracking(e);
      button.removeClass('sui-button-onload');
      e.preventDefault();
    },
    migrateComplete: function migrateComplete() {
      var slide = this.$('#hustle-dialog--migrate-slide-2'),
          self = this;
      var title = slide.find('#hustle-dialog--migrate-slide-2-title');
      var description = slide.find('#hustle-dialog--migrate-slide-2-description');
      this.$el.find('sui-button-onload').removeClass('sui-button-onload');
      title.text(title.data('done-text'));
      description.text(description.data('done-text'));
      Module.Utils.accessibleHide(slide.find('div[data-migrate-progress]'));
      Module.Utils.accessibleShow(slide.find('div[data-migrate-done]'));
      this.$el.closest('.sui-modal').on('click', function (e) {
        return self.closeDialog(e);
      });
    },
    migrateFailed: function migrateFailed() {
      var slide = this.$el.find('#hustle-dialog--migrate-slide-2'),
          description = slide.find('#dialogDescription');
      description.text('');
      Module.Utils.accessibleHide(slide.find('div[data-migrate-start]'));
      Module.Utils.accessibleShow(slide.find('div[data-migrate-failed]'));
      Module.Utils.accessibleHide(slide.find('div[data-migrate-progress]'));
      var noticeId = 'hustle-dialog--migrate-error-notice',
          $notice = $('#' + noticeId),
          message = $notice.data('message');
      Module.Notification.open('error', message, false, noticeId, false);
    },
    updateProgress: function updateProgress(migratedRows, rowsPercentage, totalRows) {
      if ('undefined' === typeof this.totalRows) {
        this.totalRows = totalRows;
        this.$el.find('#hustle-total-rows').text(totalRows);
      }

      this.$partialRows.text(migratedRows);
      var width = rowsPercentage + '%';
      this.$progressBar.css('width', width);

      if (100 >= rowsPercentage) {
        this.$progressText.text(rowsPercentage + '%');
      }
    },
    migrateTracking: function migrateTracking(e) {
      e.preventDefault();
      var self = this,
          $button = $(e.currentTarget),
          nonce = $button.data('nonce'),
          data = {
        action: 'hustle_migrate_tracking',
        _ajax_nonce: nonce
      };
      $.ajax({
        type: 'POST',
        url: ajaxurl,
        dataType: 'json',
        data: data,
        success: function success(res) {
          if (res.success) {
            var migratedRows = res.data.migrated_rows,
                migratedPercentage = res.data.migrated_percentage,
                totalRows = res.data.total_entries || '0';

            if ('done' !== res.data.current_meta) {
              self.updateProgress(migratedRows, migratedPercentage, totalRows);
              self.migrateTracking(e);
            } else {
              self.updateProgress(migratedRows, migratedPercentage, totalRows); // Set a small delay so the users can see the progress update in front before moving
              // forward and they don't think some rows were not migrated.

              setTimeout(function () {
                return self.migrateComplete();
              }, 500);
            }
          } else {
            self.migrateFailed();
          }
        },
        error: function error() {
          self.migrateFailed();
        }
      });
      return false;
    },
    createModule: function createModule(e) {
      var button = $(e.target),
          $selection = this.$el.find('.sui-box-selector input:checked');

      if ($selection.length) {
        this.dismissModal();
        button.addClass('sui-button-onload');
        var moduleType = $selection.val(),
            page = 'undefined' !== typeof optinVars.module_page[moduleType] ? optinVars.module_page[moduleType] : optinVars.module_page.popup;
        window.location = "?page=".concat(page, "&create-module=true");
      } else {// Show an error message or something?
      }

      e.preventDefault();
    },
    closeDialog: function closeDialog(e) {
      SUI.closeModal();
      e.preventDefault();
      e.stopPropagation();
    },
    enableContinue: function enableContinue() {
      this.$el.find('#hustle-create-new-module').prop('disabled', false);
    },
    dismissModal: function dismissModal(e) {
      if (e) {
        e.preventDefault();
      }

      $.post(ajaxurl, {
        action: 'hustle_dismiss_notification',
        name: 'migrate_modal',
        _ajax_nonce: this.$el.data('nonce')
      });
    }
  });
  new migrationModalView();
});
Hustle.define('Modals.Preview', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-dialog--preview',
    iframeWindow: null,
    events: {
      'click .hustle-modal-close': 'close',
      'click .hustle-preview-device-button': 'previewDeviceSelected',
      'click #hustle-preview-reload-module-button': 'reloadModuleClicked'
    },
    open: function open(moduleId, moduleType, $button) {
      var previewData = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : false;
      this.displayModuleName(previewData);
      this.maybeHideReloadButton(moduleType);
      SUI.openModal('hustle-dialog--preview', $button, null, false, false);
      var data = {
        action: 'open',
        moduleId: moduleId,
        moduleType: moduleType,
        previewData: previewData
      };
      this.initiateIframe(data);
    },
    displayModuleName: function displayModuleName(previewData) {
      if (previewData) {
        this.$('#hustle-dialog--preview-description').html(previewData.module_name || '');
      }
    },
    maybeHideReloadButton: function maybeHideReloadButton(moduleType) {
      var $reloadButton = this.$('#hustle-preview-reload-module-button');

      if ('embedded' === moduleType) {
        $reloadButton.addClass('sui-hidden-important');
      } else {
        $reloadButton.removeClass('sui-hidden-important');
      }
    },
    initiateIframe: function initiateIframe(data) {
      var _this = this;

      var $iframe = this.$('#hustle-preview-iframe'); // Load the iframe the first time it's opened only.

      if ('undefined' === typeof $iframe.attr('src')) {
        $iframe[0].src = $iframe.data('src');
        $iframe.on('load', function () {
          var $previewContainer = _this.$('#hustle-preview-iframe-container'); // Remove the "loading" container after the iframe's page loads and show the iframe.


          $previewContainer.show();
          $previewContainer.prop('aria-hidden', false);

          _this.$('#hustle-preview-loader').remove();

          _this.iframeWindow = $iframe[0].contentWindow;

          _this.talkToIframe(data);
        });
      } else {
        // Prevent the "finished loading" message from being read each time the modal is opened.
        this.$('#hustle-sr-text-preview-loaded').remove();
        this.talkToIframe(data);
      }
    },
    close: function close() {
      var _this2 = this;

      // Delay this a bit so the modal is closed before emptying the preview containers.
      setTimeout(function () {
        return _this2.talkToIframe({
          action: 'close'
        });
      }, 500);
    },
    reloadModuleClicked: function reloadModuleClicked() {
      this.talkToIframe({
        action: 'reload'
      });
    },
    previewDeviceSelected: function previewDeviceSelected(e) {
      var $button = $(e.currentTarget),
          device = $button.data('device');
      this.$('.hustle-preview-device-button').removeClass('sui-active');
      $button.addClass('sui-active');
      this.$('#hustle-sr-text-preview-selected-device').html($button.data('selected'));

      if ('desktop' === device) {
        this.$el.removeClass('hustle-preview-mobile');
        this.$el.addClass('hustle-preview-desktop');
      } else if ('mobile' === device) {
        this.$el.removeClass('hustle-preview-desktop');
        this.$el.addClass('hustle-preview-mobile');
      }
    },
    talkToIframe: function talkToIframe(message) {
      // Avoid sending messages if the iframe isn't initialized.
      if (this.iframeWindow) {
        this.iframeWindow.postMessage(message, window.location);
      }
    }
  });
});
Hustle.define('Modals.ReleaseHighlight', function ($) {
  'use strict';

  var welcomeModalView = Backbone.View.extend({
    el: '#hustle-dialog--release-highlight',
    initialize: function initialize() {
      var _this = this;

      if (!this.$el.length) {
        return;
      }

      setTimeout(function () {
        return _this.show();
      }, 100);
      this.$el.on('close', function () {
        return _this.dismissModal();
      });
    },
    show: function show() {
      var _this2 = this;

      if ('undefined' === typeof SUI) {
        setTimeout(function () {
          return _this2.show();
        }, 100);
        return;
      }

      SUI.openModal('hustle-dialog--release-highlight', $('.sui-header-title')[0], this.$('.hustle-modal-close'), true);
    },
    dismissModal: function dismissModal() {
      $.post(ajaxurl, {
        action: 'hustle_dismiss_notification',
        name: this.$el.data('name'),
        _ajax_nonce: optinVars.dismiss_notice_nonce
      });
    }
  });
  new welcomeModalView();
});
Hustle.define('Modals.ReviewConditions', function ($) {
  'use strict';

  var ReviewConditionsModalView = Backbone.View.extend({
    el: '#hustle-dialog--review_conditions',
    events: {
      'click .hustle-review-conditions-dismiss': 'dismissModal'
    },
    initialize: function initialize() {
      if (!this.$el.length) {
        return;
      }

      setTimeout(this.show, 100, this);
    },
    show: function show(reviewConditions) {
      if ('undefined' === typeof SUI || 'undefined' === typeof SUI.openModal) {
        setTimeout(reviewConditions.show, 100, reviewConditions);
        return;
      }

      SUI.openModal('hustle-dialog--review_conditions', $('.sui-header-title'));
    },
    dismissModal: function dismissModal() {
      $.post(ajaxurl, {
        action: 'hustle_dismiss_notification',
        name: '41_visibility_behavior_update',
        _ajax_nonce: this.$el.data('nonce')
      });
    }
  });
  new ReviewConditionsModalView();
});
Hustle.define('Upgrade_Modal', function () {
  'use strict';

  return Backbone.View.extend({
    el: '#wph-upgrade-modal',
    opts: {},
    events: {
      'click .wpmudev-i_close': 'close'
    },
    initialize: function initialize(options) {
      this.opts = _.extend({}, this.opts, options);
    },
    close: function close(e) {
      e.preventDefault();
      e.stopPropagation();
      this.$el.removeClass('wpmudev-modal-active');
    }
  });
});
Hustle.define('Modals.Welcome', function ($) {
  'use strict';

  var welcomeModalView = Backbone.View.extend({
    el: '#hustle-dialog--welcome',
    events: {
      'click #hustle-new-create-module': 'createModule',
      'click .sui-box-selector': 'enableContinue',
      'click #getStarted': 'dismissModal',
      'click .sui-modal-skip': 'dismissModal',
      'click .hustle-button-dismiss-welcome': 'dismissModal'
    },
    initialize: function initialize() {
      if (!this.$el.length) {
        return;
      }

      setTimeout(this.show, 100, this);
    },
    show: function show(self) {
      if ('undefined' === typeof SUI) {
        setTimeout(self.show, 100, self);
        return;
      }

      SUI.openModal('hustle-dialog--welcome', $('.sui-header-title')[0], self.$('#hustle-dialog--welcome-first .sui-button-icon.hustle-button-dismiss-welcome'), true);
      SUI.slideModal('hustle-dialog--welcome-first');
    },
    createModule: function createModule(e) {
      var button = $(e.target),
          $selection = this.$el.find('.sui-box-selector input:checked');

      if ($selection.length) {
        button.addClass('sui-button-onload');
        var moduleType = $selection.val(),
            page = 'undefined' !== typeof optinVars.module_page[moduleType] ? optinVars.module_page[moduleType] : optinVars.module_page.popup;
        window.location = "?page=".concat(page, "&create-module=true");
      }

      e.preventDefault();
    },
    enableContinue: function enableContinue() {
      this.$el.find('#hustle-new-create-module').prop('disabled', false);
    },
    dismissModal: function dismissModal(e) {
      if (e) {
        e.preventDefault();
      }

      $.post(ajaxurl, {
        action: 'hustle_dismiss_notification',
        name: 'welcome_modal',
        _ajax_nonce: this.$el.data('nonce')
      });
    }
  });
  new welcomeModalView();
});
(function ($) {
  'use strict';

  Optin.View = {};
  Optin.View.Conditions = Optin.View.Conditions || {};
  var ConditionBase = Hustle.View.extend({
    conditionId: '',
    className: 'sui-builder-field sui-accordion-item sui-accordion-item--open',
    _template: Optin.template('hustle-visibility-rule-tpl'),
    template: false,
    _defaults: {
      typeName: '',
      conditionName: ''
    },
    _events: {
      'change input': 'changeInput',
      'change textarea': 'changeInput',
      'change select': 'changeInput'
    },
    init: function init(opts) {
      this.undelegateEvents();
      this.$el.removeData().off();
      this.type = opts.type;
      this.groupId = opts.groupId;
      this.filter_type = opts.filter_type; // eslint-disable-line camelcase

      this.id = this.conditionId;
      this.template = 'undefined' !== typeof this.cpt ? Optin.template('hustle-visibility-rule-tpl--post_type') : Optin.template('hustle-visibility-rule-tpl--' + this.conditionId);
      /**
       * Defines typeName and conditionName based on type and id so that it can be used in the template later on
       *
       * @type {Object}
       * @private
       */

      this._defaults = {
        typeName: optinVars.module_type_name,
        conditionName: optinVars.messages.conditions[this.conditionId] ? optinVars.messages.conditions[this.conditionId] : this.conditionId,
        groupId: this.groupId,
        id: this.conditionId,
        source: opts.source
      };
      this.data = this.getData();
      this.render();
      this.events = $.extend(true, {}, this.events, this._events);
      this.delegateEvents();

      if (this.onInit && _.isFunction(this.onInit)) {
        this.onInit.apply(this, arguments);
      }

      return this;
    },
    getData: function getData() {
      return _.extend({}, this._defaults, this.defaults(), this.model.get(this.conditionId), {
        type: this.type
      });
    },
    getTitle: function getTitle() {
      return this.title.replace('{type_name}', this.data.typeName);
    },
    getBody: function getBody() {
      return 'function' === typeof this.body ? this.body.apply(this, arguments) : this.body.replace('{type_name}', this.data.typeName);
    },
    getHeader: function getHeader() {
      return this.header;
    },
    countLines: function countLines(value) {
      // trim trailing return char if exists
      var text = value.replace(/\s+$/g, '');
      var split = text.split('\n');
      return split.length;
    },
    render: function render() {
      this.setProperties();

      var html = this._template(_.extend({}, {
        title: this.getTitle(),
        body: this.getBody(),
        header: this.getHeader()
      }, this._defaults, {
        type: this.type
      }));

      this.$el.html('');
      this.$el.html(html);
      $('.wph-conditions--box .wph-conditions--item:not(:last-child)').removeClass('wph-conditions--open').addClass('wph-conditions--closed');
      $('.wph-conditions--box .wph-conditions--item:not(:last-child) section').hide();

      if (this.rendered && 'function' === typeof this.rendered) {
        this.rendered.apply(this, arguments);
      }

      return this;
    },

    /**
     * Updates attribute value into the condition hash
     *
     * @param {string} attribute Name of the attribute to update.
     * @param {*} val New value of the attribute.
     */
    updateAttribute: function updateAttribute(attribute, val) {
      this.data = this.model.get(this.conditionId);
      this.data[attribute] = val;
      this.model.set(this.conditionId, this.data); // TODO: instead of triggering manually, clone the retrieved object so
      // backbone recognizes the change.

      this.model.trigger('change');
    },
    getAttribute: function getAttribute(attribute) {
      var data = this.model.get(this.conditionId);
      return data && data[attribute] ? data[attribute] : false;
    },
    refreshLabel: function refreshLabel() {
      var html = this.getHeader();
      this.$el.find('.wph-condition--preview').html('');
      this.$el.find('.sui-accordion-item-header .sui-tag').html(html);
    },

    /**
     * Triggered on input change
     *
     * @param {event} e Event.
     */
    changeInput: function changeInput(e) {
      var el = e.target,
          $el = $(el);
      var val = $el.is('.sui-select') ? $el.val() : e.target.value; //stop handler in /assets/js/admin/mixins/model-updater.js

      e.stopImmediatePropagation();

      if ($el.is(':checkbox')) {
        val = $el.is(':checked');
      } // skip for input search


      if ($el.is('.select2-search__field')) {
        return false;
      }

      var attribute = el.getAttribute('data-attribute');
      this.updateAttribute(attribute, val);
      this.refreshLabel();
    },

    /**
     * Returns configs of condition
     *
     * @return {Object|boolean} The configs value, or true if not set.
     */
    getConfigs: function getConfigs() {
      return this.defaults() || true;
    }
  });

  var reenableScroll = function reenableScroll() {
    /**
     * reenable scrolling for the container
     * select2 disables scrolling after select so we reenable it
     */
    $('.wph-conditions--items').data('select2ScrollPosition', {});
  },
      ToggleButtonTogglerMixin = {
    events: {
      'change input[type="radio"]': 'setCurrentLi'
    },
    setCurrentLi: function setCurrentLi(e) {
      var $this = $(e.target),
          $li = $this.closest('li');
      $li.siblings().removeClass('current');
      $li.toggleClass('current', $this.is(':checked'));
    }
  };
  /**
   * Posts
   */


  Optin.View.Conditions.posts = ConditionBase.extend(_.extend({}, ToggleButtonTogglerMixin, {
    conditionId: 'posts',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.posts;
    },
    defaults: function defaults() {
      return {
        filter_type: 'except',
        // except | only
        posts: []
      };
    },
    onInit: function onInit() {//this.listenTo( this.model, 'change', this.render );
    },
    getHeader: function getHeader() {
      if (this.getAttribute('posts').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('posts').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.hustle-select-ajax').SUIselect2({
        tags: 'true',
        width: '100%',
        dropdownCssClass: 'sui-select-dropdown',
        ajax: {
          url: ajaxurl,
          delay: 250,
          // wait 250 milliseconds before triggering the request
          dataType: 'json',
          type: 'POST',
          data: function data(params) {
            var query = {
              action: 'get_new_condition_ids',
              search: params.term,
              postType: 'post'
            };
            return query;
          },
          processResults: function processResults(data) {
            return {
              results: data.data
            };
          },
          cache: true
        },
        createTag: function createTag() {
          return false;
        }
      }).on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  }));
  /**
   * Pages
   */

  Optin.View.Conditions.pages = ConditionBase.extend(_.extend({}, ToggleButtonTogglerMixin, {
    conditionId: 'pages',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.pages;
    },
    defaults: function defaults() {
      return {
        filter_type: 'except',
        // except | only
        pages: []
      };
    },
    onInit: function onInit() {//this.listenTo( this.model, 'change', this.render );
    },
    getHeader: function getHeader() {
      if (this.getAttribute('pages').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('pages').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.hustle-select-ajax').SUIselect2({
        tags: 'true',
        width: '100%',
        dropdownCssClass: 'sui-select-dropdown',
        ajax: {
          url: ajaxurl,
          delay: 250,
          // wait 250 milliseconds before triggering the request
          dataType: 'json',
          type: 'POST',
          data: function data(params) {
            var query = {
              action: 'get_new_condition_ids',
              search: params.term,
              postType: 'page'
            };
            return query;
          },
          processResults: function processResults(data) {
            return {
              results: data.data
            };
          },
          cache: true
        },
        createTag: function createTag() {
          return false;
        }
      }).on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  }));
  /**
   * Custom Post Types
   */

  if (optinVars.post_types) {
    _.each(optinVars.post_types, function (cptDetails, cpt) {
      Optin.View.Conditions[cptDetails.name] = ConditionBase.extend(_.extend({}, ToggleButtonTogglerMixin, {
        conditionId: cptDetails.name,
        cpt: true,
        setProperties: function setProperties() {
          this.title = cptDetails.label;
        },
        defaults: function defaults() {
          return {
            filter_type: 'except',
            // except | only
            selected_cpts: [],
            postType: cpt,
            postTypeLabel: cptDetails.label
          };
        },
        getHeader: function getHeader() {
          if (this.getAttribute('selected_cpts').length) {
            return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('selected_cpts').length);
          }

          return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
        },
        body: function body() {
          return this.template(this.getData());
        },
        rendered: function rendered() {
          this.$('.hustle-select-ajax').SUIselect2({
            tags: 'true',
            width: '100%',
            dropdownCssClass: 'sui-select-dropdown',
            ajax: {
              url: ajaxurl,
              delay: 250,
              // wait 250 milliseconds before triggering the request
              dataType: 'json',
              type: 'POST',
              data: function data(params) {
                var query = {
                  action: 'get_new_condition_ids',
                  search: params.term,
                  postType: cpt
                };
                return query;
              },
              processResults: function processResults(data) {
                return {
                  results: data.data
                };
              },
              cache: true
            },
            createTag: function createTag() {
              return false;
            }
          }).on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
        }
      }));
    });
  }
  /**
   * Categories
   */


  Optin.View.Conditions.categories = ConditionBase.extend(_.extend({}, ToggleButtonTogglerMixin, {
    conditionId: 'categories',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.categories;
    },
    defaults: function defaults() {
      return {
        filter_type: 'except',
        // except | only
        categories: []
      };
    },
    onInit: function onInit() {//this.listenTo( this.model, 'change', this.render );
    },
    getHeader: function getHeader() {
      if (this.getAttribute('categories').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('categories').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.hustle-select-ajax').SUIselect2({
        tags: 'true',
        width: '100%',
        dropdownCssClass: 'sui-select-dropdown',
        ajax: {
          url: ajaxurl,
          delay: 250,
          // wait 250 milliseconds before triggering the request
          dataType: 'json',
          type: 'POST',
          data: function data(params) {
            var query = {
              action: 'get_new_condition_ids',
              search: params.term,
              postType: 'category'
            };
            return query;
          },
          processResults: function processResults(data) {
            return {
              results: data.data
            };
          },
          cache: true
        },
        createTag: function createTag() {
          return false;
        }
      }).on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  }));
  /**
   * Tags
   */

  Optin.View.Conditions.tags = ConditionBase.extend(_.extend({}, ToggleButtonTogglerMixin, {
    conditionId: 'tags',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.tags;
    },
    defaults: function defaults() {
      return {
        filter_type: 'except',
        // except | only
        tags: []
      };
    },
    onInit: function onInit() {//this.listenTo( this.model, 'change', this.render );
    },
    getHeader: function getHeader() {
      if (this.getAttribute('tags').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('tags').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.hustle-select-ajax').SUIselect2({
        width: '100%',
        tags: 'true',
        dropdownCssClass: 'sui-select-dropdown',
        ajax: {
          url: ajaxurl,
          delay: 250,
          // wait 250 milliseconds before triggering the request
          dataType: 'json',
          type: 'POST',
          data: function data(params) {
            var query = {
              action: 'get_new_condition_ids',
              search: params.term,
              postType: 'tag'
            };
            return query;
          },
          processResults: function processResults(data) {
            return {
              results: data.data
            };
          },
          cache: true
        },
        createTag: function createTag() {
          return false;
        }
      }).on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  }));
  /**
   * Visitor logged in / not logged in
   */

  Optin.View.Conditions.visitor_logged_in_status = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'visitor_logged_in_status',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.visitor_logged_in;
    },
    defaults: function defaults() {
      return {
        show_to: 'logged_in'
      };
    },
    getHeader: function getHeader() {
      if (this.getAttribute('show_to').length && 'logged_out' === this.getAttribute('show_to')) {
        return optinVars.messages.condition_labels.logged_out;
      }

      return optinVars.messages.condition_labels.logged_in;
    },
    body: function body() {
      return this.template(this.getData());
    }
  });
  /**
   * Amount of times the module has been shown to the same visitor
   */

  Optin.View.Conditions.shown_less_than = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'shown_less_than',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.shown_less_than;
    },
    defaults: function defaults() {
      return {
        less_or_more: 'less_than',
        less_than: ''
      };
    },
    getHeader: function getHeader() {
      if (0 < this.getAttribute('less_than')) {
        if ('less_than' === this.getAttribute('less_or_more')) {
          return optinVars.messages.condition_labels.number_views.replace('{number}', this.getAttribute('less_than'));
        }

        return optinVars.messages.condition_labels.number_views_more.replace('{number}', this.getAttribute('less_than'));
      }

      return optinVars.messages.condition_labels.any;
    },
    body: function body() {
      return this.template(this.getData());
    }
  });
  /**
   * Visitor is on mobile / desktop
   */

  Optin.View.Conditions.visitor_device = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'visitor_device',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.only_on_mobile;
    },
    defaults: function defaults() {
      return {
        filter_type: 'mobile' // mobile | not_mobile

      };
    },
    getHeader: function getHeader() {
      if ('not_mobile' === this.getAttribute('filter_type')) {
        return optinVars.messages.condition_labels.desktop_only;
      }

      return optinVars.messages.condition_labels.mobile_only;
    },
    body: function body() {
      return this.template(this.getData());
    }
  });
  /**
   * From referrer
   */

  Optin.View.Conditions.from_referrer = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'from_referrer',
    disable: ['from_referrer'],
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.from_specific_ref;
    },
    defaults: function defaults() {
      return {
        filter_type: 'true',
        // true | false
        refs: ''
      };
    },
    getHeader: function getHeader() {
      var length = 0;

      if (this.getAttribute('refs').length) {
        length = this.countLines(this.getAttribute('refs'));
      }

      if (length) {
        return ('false' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.except_these : optinVars.messages.condition_labels.only_these).replace('{number}', length);
      }

      return 'false' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.any : optinVars.messages.condition_labels.none;
    },
    body: function body() {
      return this.template(this.getData());
    }
  });
  /**
   * Source of arrival
   */

  Optin.View.Conditions.source_of_arrival = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'source_of_arrival',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.from_search_engine;
    },
    defaults: function defaults() {
      return {
        source_direct: 'false',
        // true | false
        source_external: 'false',
        // true | false
        source_internal: 'false',
        // true | false
        source_not_search: 'false',
        // true | false
        source_search: 'false' // true | false

      };
    },
    getHeader: function getHeader() {
      var conditions = 0;
      var direct = _.isTrue(this.getAttribute('source_direct')) && ++conditions,
          external = _.isTrue(this.getAttribute('source_external')) && ++conditions,
          internal = _.isTrue(this.getAttribute('source_internal')) && ++conditions,
          search = _.isTrue(this.getAttribute('source_search')) && ++conditions,
          notSearch = _.isTrue(this.getAttribute('source_not_search')) && ++conditions;

      if (search && notSearch || direct && internal && external) {
        return optinVars.messages.condition_labels.any;
      } else if (conditions) {
        return optinVars.messages.condition_labels.any_conditions.replace('{number}', conditions);
      }

      return optinVars.messages.condition_labels.any;
    },
    body: function body() {
      return this.template(this.getData());
    }
  });
  /**
   * On/not on specific url
   */

  Optin.View.Conditions.on_url = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'on_url',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.on_specific_url;
    },
    defaults: function defaults() {
      return {
        filter_type: 'except',
        // except | only
        urls: ''
      };
    },
    getHeader: function getHeader() {
      var length = 0;

      if (this.getAttribute('urls').length) {
        length = this.countLines(this.getAttribute('urls'));
      }

      if (length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    }
  });
  /**
   * On/not on specific browser
   */

  Optin.View.Conditions.on_browser = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'on_browser',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.on_specific_browser;
    },
    defaults: function defaults() {
      return {
        browsers: '',
        filter_type: 'except' // except | only

      };
    },
    getHeader: function getHeader() {
      if (this.getAttribute('browsers').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('browsers').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.sui-select').val(this.getAttribute('browsers'));
      SUI.select.init(this.$('.sui-select'));
      this.$('.sui-select').on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  });
  /**
   * Visitor commented or not
   */

  Optin.View.Conditions.visitor_commented = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'visitor_commented',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.visitor_has_never_commented;
    },
    defaults: function defaults() {
      return {
        filter_type: 'true' // true | false

      };
    },
    getHeader: function getHeader() {
      return 'false' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.false : optinVars.messages.condition_labels.true;
    },
    body: function body() {
      return this.template(this.getData());
    }
  });
  /**
   * User has role
   */

  Optin.View.Conditions.user_roles = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'user_roles',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.on_specific_roles;
    },
    defaults: function defaults() {
      return {
        roles: '',
        filter_type: 'except' // except | only

      };
    },
    getHeader: function getHeader() {
      if (this.getAttribute('roles').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('roles').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.sui-select').val(this.getAttribute('roles'));
      SUI.select.init(this.$('.sui-select'));
      this.$('.sui-select').on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  });
  /**
   * Page templates
   */

  Optin.View.Conditions.page_templates = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'page_templates',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.on_specific_templates;
    },
    defaults: function defaults() {
      return {
        templates: '',
        filter_type: 'except' // except | only

      };
    },
    getHeader: function getHeader() {
      if (this.getAttribute('templates').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('templates').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.sui-select').val(this.getAttribute('templates'));
      SUI.select.init(this.$('.sui-select'));
      this.$('.sui-select').on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  });
  /**
   * Show modules based on user registration time
   */

  Optin.View.Conditions.user_registration = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'user_registration',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.user_registration;
    },
    defaults: function defaults() {
      return {
        from_date: 0,
        to_date: 0
      };
    },
    getHeader: function getHeader() {
      var from = 0 < this.getAttribute('from_date') ? optinVars.messages.condition_labels.reg_date.replace('{number}', this.getAttribute('from_date')) : optinVars.messages.condition_labels.immediately;
      var upTo = 0 < this.getAttribute('to_date') ? optinVars.messages.condition_labels.reg_date.replace('{number}', this.getAttribute('to_date')) : optinVars.messages.condition_labels.forever;
      return from + ' - ' + upTo;
    },
    body: function body() {
      return this.template(this.getData());
    }
  });
  /**
   * Visitor country
   */

  Optin.View.Conditions.visitor_country = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'visitor_country',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.not_in_a_country;
    },
    defaults: function defaults() {
      return {
        countries: '',
        filter_type: 'except' // only | except

      };
    },
    getHeader: function getHeader() {
      if (this.getAttribute('countries').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('countries').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.sui-select').val(this.getAttribute('countries'));
      SUI.select.init(this.$('.sui-select'));
      this.$('.sui-select').on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  });
  /**
   * Static Pages
   */

  Optin.View.Conditions.wp_conditions = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'wp_conditions',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.wp_conditions;
    },
    defaults: function defaults() {
      return {
        wp_conditions: '',
        filter_type: 'except' // except | only

      };
    },
    getHeader: function getHeader() {
      if (this.getAttribute('wp_conditions').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('wp_conditions').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.sui-select').val(this.getAttribute('wp_conditions'));
      SUI.select.init(this.$('.sui-select'));
      this.$('.sui-select').on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  });
  /**
   * Archive Pages
   */

  Optin.View.Conditions.archive_pages = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'archive_pages',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.archive_pages;
    },
    defaults: function defaults() {
      return {
        archive_pages: '',
        filter_type: 'except' // except | only

      };
    },
    getHeader: function getHeader() {
      if (this.getAttribute('archive_pages').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('archive_pages').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.sui-select').val(this.getAttribute('archive_pages'));
      SUI.select.init(this.$('.sui-select'));
      this.$('.sui-select').on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  });
  /**********************************************************************************************************************************************************/

  /*********************************** WooCommerce Conditions ***********************************************************************************************/

  /**********************************************************************************************************************************************************/

  /**
   * All WooCommerce Pages
   */

  Optin.View.Conditions.wc_pages = ConditionBase.extend(_.extend({}, ToggleButtonTogglerMixin, {
    // eslint-disable-line camelcase
    conditionId: 'wc_pages',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.wc_pages;
    },
    defaults: function defaults() {
      return {
        filter_type: 'all' // all | none

      };
    },
    getHeader: function getHeader() {
      if ('none' === this.getAttribute('filter_type')) {
        return optinVars.messages.condition_labels.none;
      }

      return optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    }
  }));
  /**
   * WooCommerce Categories
   */

  Optin.View.Conditions.wc_categories = ConditionBase.extend(_.extend({}, ToggleButtonTogglerMixin, {
    // eslint-disable-line camelcase
    conditionId: 'wc_categories',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.wc_categories;
    },
    defaults: function defaults() {
      return {
        filter_type: 'except',
        // except | only
        wc_categories: [] // eslint-disable-line camelcase

      };
    },
    onInit: function onInit() {},
    getHeader: function getHeader() {
      if (this.getAttribute('wc_categories').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('wc_categories').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.hustle-select-ajax').SUIselect2({
        tags: 'true',
        width: '100%',
        ajax: {
          url: ajaxurl,
          delay: 250,
          // wait 250 milliseconds before triggering the request
          dataType: 'json',
          type: 'POST',
          data: function data(params) {
            var query = {
              action: 'get_new_condition_ids',
              search: params.term,
              postType: 'wc_category'
            };
            return query;
          },
          processResults: function processResults(data) {
            return {
              results: data.data
            };
          },
          cache: true
        },
        createTag: function createTag() {
          return false;
        }
      }).on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  }));
  /**
   * WooCommerce Tags
   */

  Optin.View.Conditions.wc_tags = ConditionBase.extend(_.extend({}, ToggleButtonTogglerMixin, {
    // eslint-disable-line camelcase
    conditionId: 'wc_tags',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.wc_tags;
    },
    defaults: function defaults() {
      return {
        filter_type: 'except',
        // except | only
        wc_tags: [] // eslint-disable-line camelcase

      };
    },
    onInit: function onInit() {},
    getHeader: function getHeader() {
      if (this.getAttribute('wc_tags').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('wc_tags').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.hustle-select-ajax').SUIselect2({
        tags: 'true',
        width: '100%',
        dropdownCssClass: 'sui-select-dropdown',
        ajax: {
          url: ajaxurl,
          delay: 250,
          // wait 250 milliseconds before triggering the request
          dataType: 'json',
          type: 'POST',
          data: function data(params) {
            var query = {
              action: 'get_new_condition_ids',
              search: params.term,
              postType: 'wc_tag'
            };
            return query;
          },
          processResults: function processResults(data) {
            return {
              results: data.data
            };
          },
          cache: true
        },
        createTag: function createTag() {
          return false;
        }
      }).on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  }));
  /**
   * WooCommerce Archive Pages
   */

  Optin.View.Conditions.wc_archive_pages = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'wc_archive_pages',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.wc_archive_pages;
    },
    defaults: function defaults() {
      return {
        wc_archive_pages: '',
        filter_type: 'except' // except | only

      };
    },
    getHeader: function getHeader() {
      if (this.getAttribute('wc_archive_pages').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('wc_archive_pages').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.sui-select').val(this.getAttribute('wc_archive_pages'));
      SUI.select.init(this.$('.sui-select'));
      this.$('.sui-select').on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  });
  /**
   * WooCommerce Static Pages
   */

  Optin.View.Conditions.wc_static_pages = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'wc_static_pages',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.wc_static_pages;
    },
    defaults: function defaults() {
      return {
        wc_static_pages: '',
        filter_type: 'except' // except | only

      };
    },
    getHeader: function getHeader() {
      if (this.getAttribute('wc_static_pages').length) {
        return ('only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.only_these : optinVars.messages.condition_labels.except_these).replace('{number}', this.getAttribute('wc_static_pages').length);
      }

      return 'only' === this.getAttribute('filter_type') ? optinVars.messages.condition_labels.none : optinVars.messages.condition_labels.all;
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      this.$('.sui-select').val(this.getAttribute('wc_static_pages'));
      SUI.select.init(this.$('.sui-select'));
      this.$('.sui-select').on('select2:selecting', reenableScroll).on('select2:unselecting', reenableScroll);
    }
  });
  /**
   * Cookie is set
   */

  Optin.View.Conditions.cookie_set = ConditionBase.extend({
    // eslint-disable-line camelcase
    conditionId: 'cookie_set',
    setProperties: function setProperties() {
      this.title = optinVars.messages.conditions.cookie_set;
    },
    defaults: function defaults() {
      return {
        cookie_name: '',
        cookie_value: '',
        filter_type: 'exists',
        // exists | doesnt_exists
        cookie_value_conditions: 'anything'
      };
    },
    changeInput: function changeInput(e) {
      var el = e.target,
          $el = $(el);
      var updated,
          $selectedTabInput,
          $selectedTabInputValue,
          $cookieNameInput,
          val = $el.is('.sui-select') ? $el.val() : e.target.value;
      e.stopImmediatePropagation(); // Because cookies condition uses two inputs based on which condition type is selected
      // we have to update a value based on currently selected option.

      if ('undefined' !== typeof $el.find(':selected').data('switcher-menu')) {
        $selectedTabInput = $el.closest('.select-content-switcher-wrapper').find(".select-switcher-content[data-switcher-content=\"".concat($el.find(':selected').data('switcher-menu'), "\"] input"));
        $selectedTabInputValue = $selectedTabInput.val();
        $selectedTabInputValue = $selectedTabInputValue ? $selectedTabInputValue : '';
        updated = this.updateAttribute('cookie_value', $selectedTabInputValue);
      } // Let's make sure we use the proper cookie name.


      if ('filter_type' === $el.data('attribute')) {
        $cookieNameInput = $el.closest('.sui-side-tabs').find('.sui-tab-boxed:not(.active) input[data-attribute="cookie_name"]').val();
        $el.closest('.sui-side-tabs').find('.sui-tab-boxed.active input[data-attribute="cookie_name"]').val($cookieNameInput);
        updated = this.updateAttribute('cookie_name', $cookieNameInput);
      }

      if ($el.is(':checkbox')) {
        val = $el.is(':checked');
      } // skip for input search


      if ($el.is('.select2-search__field')) {
        return false;
      }

      var attribute = el.getAttribute('data-attribute');
      updated = this.updateAttribute(attribute, val);
      this.refreshLabel();
      return updated;
    },
    getHeader: function getHeader() {
      if (this.getAttribute('cookie_name')) {
        if ('exists' === this.getAttribute('filter_type')) {
          if ('anything' === this.getAttribute('cookie_value_conditions')) {
            return optinVars.messages.condition_labels.cookie_anything.replace('{name}', this.getAttribute('cookie_name')).replace(/(<([^>]+)>)/ig, '');
          }

          return optinVars.messages.condition_labels.cookie_value.replace('{name}', this.getAttribute('cookie_name')).replace('{value_condition}', optinVars.wp_cookie_set[this.getAttribute('cookie_value_conditions')]).replace('{value}', this.getAttribute('cookie_value')).replace(/(<([^>]+)>)/ig, '');
        }

        return optinVars.messages.condition_labels.cookie_doesnt_exist.replace('{name}', this.getAttribute('cookie_name')).replace(/(<([^>]+)>)/ig, '');
      }

      return '-';
    },
    body: function body() {
      return this.template(this.getData());
    },
    rendered: function rendered() {
      SUI.select.init(this.$('.sui-select'));
    }
  });
  $(document).trigger('hustleAddViewConditions', [ConditionBase]);
})(jQuery);
Hustle.define('imageUploader', function () {
  'use strict';

  return Backbone.View.extend({
    events: {
      'click .hustle-image-uploader-browse': 'open',
      'click .hustle-image-uploader-clear': 'clear'
    },
    mediaFrame: false,
    initialize: function initialize(options) {
      this.attribute = options.attribute;

      if (!this.model || !this.attribute) {
        throw new Error('Undefined model or attribute.');
      }

      this.render();
    },
    render: function render() {
      this.defineMediaFrame();
      return this;
    },
    // If no image is set, show the upload button. Display the selected image otherwise.
    showImagePreviewOrButton: function showImagePreviewOrButton() {
      var selectedImage = this.model.get(this.attribute);

      if ('' === selectedImage || 'undefined' === typeof selectedImage) {
        this.$el.removeClass('sui-has_file');
      } else {
        this.$el.addClass('sui-has_file');
      }
    },
    defineMediaFrame: function defineMediaFrame() {
      var self = this;
      this.mediaFrame = wp.media({
        title: optinVars.media_uploader.select_or_upload,
        button: {
          text: optinVars.media_uploader.use_this_image
        },
        multiple: false
      }).on('select', function () {
        var media = self.mediaFrame.state().get('selection').first().toJSON();
        var imageSrc, imageThumbnail;

        if (media && media.url) {
          imageSrc = media.url;
          imageThumbnail = '';
          self.model.set(self.attribute, imageSrc);

          if (media.sizes && media.sizes.thumbnail && media.sizes.thumbnail.url) {
            imageThumbnail = media.sizes.thumbnail.url;
          }

          self.$el.find('.sui-upload-file .hustle-upload-file-url').text(imageSrc);
          self.$el.find('.sui-image-preview').css('background-image', 'url( ' + imageThumbnail + ' )');
          self.showImagePreviewOrButton();
        }
      });
    },
    open: function open(e) {
      e.preventDefault();
      this.mediaFrame.open();
    },
    clear: function clear(e) {
      e.preventDefault();
      this.model.set(this.attribute, '');
      this.$el.find('.sui-upload-file .hustle-upload-file-url').text('');
      this.$el.find('.sui-image-preview').css('background-image', 'url()');
      this.showImagePreviewOrButton();
    }
  });
});
/* global tinyMCE */
Hustle.define('Modals.Edit_Field', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-dialog--edit-field',
    events: {
      'change input[name="time_format"]': 'changeTimeFormat',
      'blur input[name="name"]': 'trimName',
      'change input': 'fieldUpdated',
      'click input[type="radio"]': 'fieldUpdated',
      'change select': 'fieldUpdated',
      'change input[name="version"]': 'handleCaptchaSave'
    },
    initialize: function initialize(options) {
      var _this = this;

      this.field = options.field;
      this.changed = {}; // Same as this.field, but with the values for the field's view. Won't be stored.

      this.fieldData = options.fieldData;
      this.model = options.model;
      this.render();
      this.$el.off('close').on('close', function () {
        return _this.modalClosed();
      });
      this.$('#hustle-apply-changes').off('mouseup').on('mouseup', function (e) {
        return _this.applyChanges(e);
      });
    },
    render: function render() {
      this.renderHeader();
      this.renderLabels();
      this.renderSettings();
      this.renderStyling();
      this.handleCaptchaSave(); //select the first tab

      this.$('.hustle-data-pane').first().trigger('click'); // Make the search box work within the modal.

      SUI.select.init(this.$('.sui-select'));
    },
    renderHeader: function renderHeader() {
      var $tagContainer = this.$('.hustle-field-tag-container');

      if (!$tagContainer.length) {
        this.$('.sui-box-header').append('<div class="sui-actions-left hustle-field-tag-container"><span class="sui-tag"></span></div>');
      }

      this.$('.sui-box-header .sui-tag').text(this.field.type);
    },
    renderLabels: function renderLabels() {
      if (-1 !== $.inArray(this.field.type, ['recaptcha', 'gdpr', 'submit'])) {
        this.$('#hustle-data-tab--labels').removeClass('hustle-data-pane').addClass('sui-hidden');
        this.$('#hustle-data-pane--labels').addClass('sui-hidden');
        return;
      }

      this.$('#hustle-data-tab--labels').removeClass('sui-hidden').addClass('hustle-data-pane');
      this.$('#hustle-data-pane--labels').removeClass('sui-hidden'); // Check if a specific template for this field exists.

      var templateId = 'hustle-' + this.field.type + '-field-labels-tpl'; // If a specific template doesn't exist, use the common template.

      if (!$('#' + templateId).length) {
        templateId = 'hustle-common-field-labels-tpl';
      }

      var template = Optin.template(templateId);
      this.$('#hustle-data-pane--labels').html(template(this.fieldData));
      Hustle.Events.trigger('view.rendered', this);
    },
    renderSettings: function renderSettings() {
      if ('hidden' === this.field.type) {
        this.$('#hustle-data-tab--settings').removeClass('hustle-data-pane').addClass('sui-hidden');
        this.$('#hustle-data-pane--settings').addClass('sui-hidden');
        Module.Utils.accessibleHide(this.$('[data-tabs]'));
        return;
      }

      Module.Utils.accessibleShow(this.$('[data-tabs]'));
      this.$('#hustle-data-tab--settings').removeClass('sui-hidden').addClass('hustle-data-pane');
      this.$('#hustle-data-pane--settings').removeClass('sui-hidden'); // Fixes a bug caused by tinyMCE used in a popup.

      $(document).on('focusin', function (e) {
        if ($(e.target).closest('.wp-link-input').length) {
          e.stopImmediatePropagation();
        }
      }); // Check if a specific template for this field exists.

      var templateId = 'hustle-' + this.field.type + '-field-settings-tpl'; // If a specific template doesn't exist, use the common template.

      if (!$('#' + templateId).length) {
        templateId = 'hustle-common-field-settings-tpl';
      }

      var template = Optin.template(templateId);
      this.$('#hustle-data-pane--settings').html(template(this.fieldData));
      Hustle.Events.trigger('view.rendered', this);

      if ('gdpr' === this.field.type) {
        // These only allow inline elements.
        var editorSettings = {
          tinymce: {
            wpautop: false,
            toolbar1: 'bold,italic,strikethrough,link',
            valid_elements: 'a[href|target=_blank],strong/b,i,u,s,em,del',
            // eslint-disable-line camelcase
            forced_root_block: '' // eslint-disable-line camelcase

          },
          quicktags: {
            buttons: 'strong,em,del,link'
          }
        };
        wp.editor.remove('gdpr_message');
        wp.editor.initialize('gdpr_message', editorSettings);
      } else if ('recaptcha' === this.field.type) {
        var _editorSettings = {
          tinymce: {
            toolbar: ['bold italic link alignleft aligncenter alignright']
          },
          quicktags: true
        };
        wp.editor.remove('v3_recaptcha_badge_replacement');
        wp.editor.initialize('v3_recaptcha_badge_replacement', _editorSettings);
        wp.editor.remove('v2_invisible_badge_replacement');
        wp.editor.initialize('v2_invisible_badge_replacement', _editorSettings);
      }
    },
    renderStyling: function renderStyling() {
      if ('hidden' === this.field.type) {
        this.$('#hustle-data-tab--styling').removeClass('hustle-data-pane').addClass('sui-hidden');
        this.$('#hustle-data-pane--styling').addClass('sui-hidden');
        return;
      }

      this.$('#hustle-data-tab--styling').removeClass('sui-hidden').addClass('hustle-data-pane');
      this.$('#hustle-data-pane--styling').removeClass('sui-hidden'); // Check if a specific template for this field exists.

      var templateId = 'hustle-' + this.field.type + '-field-styling-tpl'; // If a specific template doesn't exist, use the common template.

      if (!$('#' + templateId).length) {
        templateId = 'hustle-common-field-styling-tpl';
      }

      var template = Optin.template(templateId);
      this.$('#hustle-data-pane--styling').html(template(this.fieldData));
    },
    fieldUpdated: function fieldUpdated(e) {
      var $this = $(e.target),
          dataName = $this.attr('name'),
          dataValue = $this.is(':checkbox') ? $this.is(':checked') : $this.val();
      this.changed[dataName] = dataValue;
    },
    modalClosed: function modalClosed() {
      this.undelegateEvents();
      this.stopListening();
    },
    changeTimeFormat: function changeTimeFormat(e) {
      var $this = $(e.target),
          dataValue = $this.val();

      if ('12' === dataValue) {
        $('#hustle-date-format').closest('.sui-form-field').show();
        $('input[name="time_hours"]').prop('min', 1).prop('max', 12);
      } else {
        $('#hustle-date-format').closest('.sui-form-field').hide();
        $('input[name="time_hours"]').prop('min', 0).prop('max', 23);
      }
    },
    handleCaptchaSave: function handleCaptchaSave() {
      if ('recaptcha' !== this.field.type) {
        return;
      }

      var avaiableCaptcha = $('#available_recaptchas').val();

      if (avaiableCaptcha) {
        avaiableCaptcha = avaiableCaptcha.split(',');
        var version = $('input[name="version"]:checked').val();

        if (-1 === _.indexOf(avaiableCaptcha, version)) {
          $('#hustle-dialog--edit-field').find('#hustle-apply-changes').attr('disabled', 'disabled');
        } else {
          $('#hustle-dialog--edit-field').find('#hustle-apply-changes').attr('disabled', false);
        }
      } else {
        $('#hustle-dialog--edit-field').find('#hustle-apply-changes').attr('disabled', 'disabled');
      }
    },

    /**
     * Trim and replace spaces in field name.
     *
     * @since 4.0.0
     * @param {Object} e
     */
    trimName: function trimName(e) {
      var $input = this.$(e.target),
          newVal = $input.val().trim().replace(/ /g, '_');
      $input.val(newVal);
    },

    /**
     * Add the saved settings to the model.
     *
     * @since 4.0.0
     * @param {Object} e
     */
    applyChanges: function applyChanges(e) {
      // TODO: do validation
      // TODO: keep consistency with how stuff is saved in visibility conditions
      var $button = this.$(e.target),
          formFields = Object.assign({}, this.model.get('form_elements')); // if gdpr message

      if ('gdpr' === this.field.type && 'undefined' !== typeof tinyMCE) {
        // gdpr_message editor
        var gdprMessageEditor = tinyMCE.get('gdpr_message'),
            $gdprMessageTextarea = this.$('textarea#gdpr_message'),
            gdprMessage = 'true' === $gdprMessageTextarea.attr('aria-hidden') ? gdprMessageEditor.getContent() : $gdprMessageTextarea.val();
        this.changed.gdpr_message = gdprMessage; // eslint-disable-line camelcase
      } else if ('recaptcha' === this.field.type && 'undefined' !== typeof tinyMCE) {
        // v3 recaptcha badge editor.
        var v3messageEditor = tinyMCE.get('v3_recaptcha_badge_replacement'),
            $v3messageTextarea = this.$('textarea#v3_recaptcha_badge_replacement'),
            v3message = 'true' === $v3messageTextarea.attr('aria-hidden') ? v3messageEditor.getContent() : $v3messageTextarea.val();
        this.changed.v3_recaptcha_badge_replacement = v3message; // eslint-disable-line camelcase
        // v2 invisible badge editor.

        var v2messageEditor = tinyMCE.get('v2_invisible_badge_replacement'),
            $v2messageTextarea = this.$('textarea#v2_invisible_badge_replacement'),
            v2message = 'true' === $v2messageTextarea.attr('aria-hidden') ? v2messageEditor.getContent() : $v2messageTextarea.val();
        this.changed.v2_invisible_badge_replacement = v2message; // eslint-disable-line camelcase
      } // If there were changes.


      if (Object.keys(this.changed).length) {
        var oldField = _.extend({}, this.field);

        _.extend(this.field, this.changed); // Don't allow to override Email field created by default
        // and prevent field's names from being empty.


        if ('name' in this.changed && 'email' !== oldField.name && 'email' === this.field.name || 'name' in this.changed && !this.field.name.trim().length) {
          this.field.name = oldField.name;
          delete this.changed.name;
        }

        if ('email' === oldField.name) {
          this.field.name = 'email';
          delete this.changed.name;
        }

        if (this.field.name !== oldField.name) {
          // Check if the new name already in use.
          var newOriginalName = this.field.name;
          var i = 0,
              newName = newOriginalName;

          while (newName in formFields) {
            i++;
            newName = newOriginalName + '-' + i;
          }

          this.field.name = newName;
          this.changed.name = newName;
        } // "Name" is the unique identifier. If it changed, return and let the callback handle it.


        if (!('name' in this.changed)) {
          // Update this field.
          formFields[this.field.name] = this.field; // Alternative to deep cloning the formFields object to trigger 'change' in the model.

          this.model.unset('form_elements', {
            silent: true
          });
          this.model.set('form_elements', formFields);
        }

        this.trigger('field:updated', this.field, this.changed, oldField);
      }

      $button.addClass('sui-button-onload');
      setTimeout(function () {
        return $button.removeClass('sui-button-onload');
      }, 300);
    }
  });
});
/* global moment */
Hustle.define('Modals.EditSchedule', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-schedule-dialog-content',
    dialogId: 'hustle-dialog--add-schedule',
    events: {
      'click #hustle-schedule-save': 'saveSchedule',
      'click .hustle-schedule-cancel': 'cancel',
      'click .hustle-schedule-delete': 'openDeleteModal',
      'change .hustle-datepicker-field[name=start_date]': 'changeMinDate',
      'change [name=not_schedule_start]': 'changeMinDate',
      // Change events.
      'change .hustle-checkbox-with-dependencies input[type="checkbox"]': 'checkboxWithDependenciesChanged',
      'change select[name="custom_timezone"]': 'customTimezoneChanged'
    },
    initialize: function initialize(opts) {
      this.model = opts.model;
    },
    open: function open() {
      var modalId = this.dialogId;
      var focusAfterClosed = 'hustle-schedule-focus';
      var focusWhenOpen = undefined;
      var hasOverlayMask = false;
      this.renderContent();
      $('.hustle-datepicker-field').datepicker({
        beforeShow: function beforeShow() {
          $('#ui-datepicker-div').addClass('sui-calendar');
        },
        dateFormat: 'm/d/yy'
      }); // Make the search box work within the modal.

      SUI.select.init(this.$('.sui-select'));
      this.changeMinDate();
      SUI.openModal(modalId, focusAfterClosed, focusWhenOpen, hasOverlayMask);
    },
    changeMinDate: function changeMinDate() {
      var minDate;

      if (!$('[name=not_schedule_end]').is(':checked') && !$('[name=not_schedule_start]').is(':checked')) {
        minDate = $('[name=start_date]').val();
      }

      $('.hustle-datepicker-field[name=end_date]').datepicker('option', {
        minDate: minDate
      });
    },
    renderContent: function renderContent() {
      var template = Optin.template('hustle-schedule-dialog-content-tpl'),
          $container = $('#hustle-schedule-dialog-content'),
          data = Object.assign({}, this.model.get('schedule'));
      data.is_schedule = this.model.get('is_schedule'); // eslint-disable-line camelcase

      data.serverCurrentTime = this.getTimeToDisplay('server');
      data.customCurrentTime = this.getTimeToDisplay('custom');
      this.setElement(template(data));
      $container.html(this.$el); // Bind SUI elements again.

      Hustle.Events.trigger('view.rendered', this); // We hide/show some elements on change, so keep the view displaying what it should when re-rendering the modal.

      this.refreshViewOnRender(data);
    },
    refreshViewOnRender: function refreshViewOnRender(data) {
      // Hide/show dependent elements.
      this.$('.hustle-checkbox-with-dependencies input').each(function () {
        $(this).trigger('change');
      }); // Display the correct tab.

      if ('server' === data.time_to_use) {
        $('#tab-timezone-server').click();
      } else {
        $('#tab-timezone-custom').click();
      } // Display the correct tab.


      if ('all' === data.active_days) {
        $('#tab-schedule-everyday').click();
      } else {
        $('#tab-schedule-somedays').click();
      } // Comparing the model's value with the value selected in the "select" element.


      var timezoneSelectValue = this.$('select[name="custom_timezone"]').val(),
          timezoneModelValue = data.custom_timezone; // We're retrieving the timezone options from a wp function, so we can't
      // update its selected value on js render as we do with other selects.

      if (timezoneModelValue !== timezoneSelectValue) {
        this.$('select[name="custom_timezone"]').val(timezoneModelValue).trigger('change');
      }
    },
    getTimeToDisplay: function getTimeToDisplay(source) {
      var timezone = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
      var settings = this.model.get('schedule');
      var utcOffset = false,
          currentTime = false;

      if ('server' === source) {
        utcOffset = optinVars.schedule.wp_gmt_offset || 0;
      } else {
        var customTimezone = timezone || settings.custom_timezone;

        if (customTimezone.includes('UTC')) {
          var selectedOffset = customTimezone.replace('UTC', ''); // There's a timezone with the value "UTC".

          utcOffset = selectedOffset.length ? parseFloat(selectedOffset) : 0;
        } else {
          var endMoment = moment().tz(customTimezone);
          currentTime = endMoment.format('hh:mm a');
        }
      } // Calculate the time with the manual offset.
      // Moment.js doesn't support manual offsets with decimals, so not using it here.


      if (false === currentTime && false !== utcOffset) {
        // This isn't the correct timestamp for the given offset.
        // We just want to display the time for reference.
        var timestamp = Date.now() + utcOffset * 3600 * 1000,
            _endMoment = moment.utc(timestamp);

        currentTime = _endMoment.format('hh:mm a');
      }

      return currentTime;
    },
    saveSchedule: function saveSchedule(e) {
      var $button = $(e.currentTarget),
          data = this.processFormForSave(),
          wasScheduled = '1' === this.model.get('is_schedule');
      $button.addClass('sui-button-onload');
      $button.prop('disabled', true);
      setTimeout(function () {
        $button.removeClass('sui-button-onload');
        $button.prop('disabled', false);
      }, 500);
      this.model.set('is_schedule', '1');
      this.model.set('schedule', data);
      this.model.userHasChange();
      this.closeModal(); // Display a notification only when the schedule wasn't set, but now it is.

      if (!wasScheduled) {
        Module.Notification.open('success', optinVars.schedule.new_schedule_set, false);
      }

      this.trigger('schedule:updated');
    },
    processFormForSave: function processFormForSave() {
      var $form = $('#hustle-edit-schedule-form');
      var data = Module.Utils.serializeObject($form);
      return data;
    },
    cancel: function cancel() {
      this.renderContent();
      this.closeModal();
    },
    openDeleteModal: function openDeleteModal(e) {
      var dialogId = 'hustle-dialog--delete-schedule',
          template = Optin.template('hustle-delete-schedule-dialog-content-tpl'),
          $this = $(e.currentTarget),
          data = {
        id: $this.data('id'),
        title: $this.data('title'),
        description: $this.data('description'),
        action: 'delete',
        actionClass: 'hustle-button-delete'
      },
          newFocusAfterClosed = 'hustle-schedule-notice',
          newFocusFirst = undefined,
          hasOverlayMask = true,
          content = template(data),
          footer = $('#' + dialogId + ' #hustle-delete-schedule-dialog-content'),
          deleteButton = footer.find('button.hustle-delete-confirm'); // Add the templated content to the modal.

      if (!deleteButton.length) {
        footer.append(content);
      } // Add the title to the modal.


      $('#' + dialogId + ' #hustle-dialog--delete-schedule-title').html(data.title);
      $('#' + dialogId + ' #hustle-dialog--delete-schedule-description').html(data.description);
      SUI.replaceModal(dialogId, newFocusAfterClosed, newFocusFirst, hasOverlayMask);
      $('#hustle-delete-schedule-dialog-content').off('submit').on('submit', $.proxy(this.deactivateSchedule, this));
    },
    deactivateSchedule: function deactivateSchedule(e) {
      e.preventDefault();
      this.closeModal();
      this.model.set('is_schedule', '0');
      this.model.userHasChange();
      this.trigger('schedule:updated');
    },
    checkboxWithDependenciesChanged: function checkboxWithDependenciesChanged(e) {
      var $this = $(e.currentTarget),
          disableWhenOn = $this.data('disable-on'),
          hideWhenOn = $this.data('hide-on');

      if (disableWhenOn) {
        var $dependencies = this.$("[data-checkbox-content=\"".concat(disableWhenOn, "\"]"));

        if ($this.is(':checked')) {
          $dependencies.addClass('sui-disabled');
          $dependencies.prop('disabled', true);

          if ($dependencies.parent().hasClass('select-container')) {
            $dependencies.parent().addClass('sui-disabled');
          }
        } else {
          $dependencies.removeClass('sui-disabled');
          $dependencies.prop('disabled', false);

          if ($dependencies.parent().hasClass('select-container')) {
            $dependencies.parent().removeClass('sui-disabled');
          }
        }
      }

      if (hideWhenOn) {
        var _$dependencies = this.$("[data-checkbox-content=\"".concat(hideWhenOn, "\"]"));

        if ($this.is(':checked')) {
          Module.Utils.accessibleHide(_$dependencies);
        } else {
          Module.Utils.accessibleShow(_$dependencies);
        }
      }
    },
    customTimezoneChanged: function customTimezoneChanged(e) {
      var value = $(e.currentTarget).val(),
          timeContainer = this.$('#hustle-custom-timezone-current-time'),
          currentTime = this.getTimeToDisplay('custom', value);
      timeContainer.text(currentTime);
    },
    closeModal: function closeModal() {
      $('.hustle-datepicker-field').datepicker('destroy');
      SUI.closeModal();
    }
  });
});
Hustle.define('Modals.Optin_Fields', function () {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-dialog--optin-fields',
    model: {},
    selectedFields: [],
    events: {
      'click .sui-box-selector input': 'selectFields',
      'click #hustle-insert-fields': 'insertFields'
    },
    initialize: function initialize(options) {
      var _this = this;

      this.model = options.model;
      this.selectedFields = [];
      this.$el.off('close').on('close', function () {
        return _this.closeModalActions();
      });
    },
    // TODO: don't make them selected on click, but on "Insert fields".
    selectFields: function selectFields(e) {
      var $input = this.$(e.target),
          value = $input.val(),
          $selectorLabel = this.$el.find('label[for="' + $input.attr('id') + '"]');
      $selectorLabel.toggleClass('selected');

      if ($input.prop('checked')) {
        this.selectedFields.push(value);
      } else {
        this.selectedFields = _.without(this.selectedFields, value);
      }
    },
    insertFields: function insertFields(e) {
      var // self = this,
      $button = this.$(e.target);
      $button.addClass('sui-button-onload');
      this.trigger('fields:added', this.selectedFields);
      setTimeout(function () {
        $button.removeClass('sui-button-onload');
        SUI.closeModal();
      }, 300);
    },
    closeModalActions: function closeModalActions() {
      this.undelegateEvents();
      this.stopListening();
      var selectedFieldsNames = Object.keys(this.model.get('form_elements'));
      var selector = '.sui-box-selector'; // Don't deselect reCAPTCHA if it's added.

      if (selectedFieldsNames.includes('recaptcha')) {
        selector += ':not(.hustle-optin-insert-field-label--recaptcha)';
      } // Don't deselect GDPR if it's added.


      if (selectedFieldsNames.includes('gdpr')) {
        selector += ':not(.hustle-optin-insert-field-label--gdpr)';
      }

      var $label = this.$el.find(selector),
          $input = $label.find('input');
      setTimeout(function () {
        // Uncheck options
        $label.removeClass('selected');
        $input.prop('checked', false);
        $input[0].checked = false;
      }, 200);
    }
  });
});
Hustle.define('Modals.PublishFlow', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-dialog--publish-flow',
    initialize: function initialize() {},
    open: function open() {
      var $icon = this.$('#hustle-dialog--publish-flow-icon'); // We're adding this via js to be able to use the php template, which isn't handling icons like this as of now.

      if (!$icon.length) {
        $icon = $('<span id="hustle-dialog--publish-flow-icon" class="sui-lg" aria-hidden="true" style="margin-bottom: 20px;"></span>');
        $icon.insertBefore('#hustle-dialog--publish-flow-title');
      }

      this.setLoading(); // Remove max-height from bottom image.

      this.$('.sui-box').find('.sui-image').css('max-height', '');
      SUI.openModal('hustle-dialog--publish-flow', $('.hustle-publish-button')[0], this.$('.hustle-modal-close')[0], true);
    },
    setLoading: function setLoading() {
      var $icon = this.$('#hustle-dialog--publish-flow-icon'),
          $content = this.$('.sui-box'),
          $closeButton = this.$('.sui-box-header .hustle-modal-close'),
          $title = this.$('#hustle-dialog--publish-flow-title'),
          $desc = this.$('#hustle-dialog--publish-flow-description'),
          $scheduleNotice = this.$('#hustle-published-notice-with-schedule-end');
      $icon.removeClass('sui-icon-' + $content.data('ready-icon'));
      $icon.addClass('sui-icon-' + $content.data('loading-icon'));

      if ('loader' === $content.attr('data-loading-icon')) {
        $icon.addClass('sui-loading');
      }

      $title.text($content.data('loading-title'));
      $desc.text($content.data('loading-desc'));
      $scheduleNotice.hide();
      $closeButton.hide();
    },
    setPublished: function setPublished(isScheduled, hasEnd) {
      var $icon = this.$('#hustle-dialog--publish-flow-icon'),
          $content = this.$('.sui-box'),
          $closeButton = this.$('.sui-box-header .hustle-modal-close'),
          $title = this.$('#hustle-dialog--publish-flow-title'),
          $desc = this.$('#hustle-dialog--publish-flow-description'),
          $scheduleNotice = this.$('#hustle-published-notice-with-schedule-end'),
          descText = !isScheduled ? $content.data('ready-desc') : $content.data('ready-desc-alt');
      $icon.removeClass('sui-icon-' + $content.data('loading-icon'));
      $icon.addClass('sui-icon-' + $content.data('ready-icon'));

      if ('loader' === $content.attr('data-loading-icon')) {
        $icon.removeClass('sui-loading');
      } // Display the notice for when the schedule has an end.


      if (isScheduled && hasEnd) {
        $content.find('.sui-image').css('max-height', '120px');
        $scheduleNotice.show();
      } else {
        $scheduleNotice.hide();
      }

      $title.text($content.data('ready-title'));
      $desc.text(descText); // Focus ready title
      // This will help screen readers know when module has been published

      $title.focus();
      $closeButton.show();
    }
  });
});
function _createForOfIteratorHelper(o, allowArrayLike) { var it; if (typeof Symbol === "undefined" || o[Symbol.iterator] == null) { if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || allowArrayLike && o && typeof o.length === "number") { if (it) o = it; var i = 0; var F = function F() {}; return { s: F, n: function n() { if (i >= o.length) return { done: true }; return { done: false, value: o[i++] }; }, e: function e(_e) { throw _e; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var normalCompletion = true, didErr = false, err; return { s: function s() { it = o[Symbol.iterator](); }, n: function n() { var step = it.next(); normalCompletion = step.done; return step; }, e: function e(_e2) { didErr = true; err = _e2; }, f: function f() { try { if (!normalCompletion && it.return != null) it.return(); } finally { if (didErr) throw err; } } }; }

function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }

function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) { arr2[i] = arr[i]; } return arr2; }

Hustle.define('Modals.Visibility_Conditions', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-dialog--visibility-options',
    selectedConditions: [],
    opts: {
      groupId: 0,
      conditions: []
    },
    events: {
      'click .sui-box-selector input': 'selectConditions'
    },
    initialize: function initialize(options) {
      $('#hustle-add-conditions').off('click').on('click', $.proxy(this.addConditions, this));
      this.opts = _.extend({}, this.opts, options);
      this.selectedConditions = this.opts.conditions;
      this.$('.hustle-visibility-condition-option').prop('checked', false).prop('disabled', false);

      var _iterator = _createForOfIteratorHelper(this.selectedConditions),
          _step;

      try {
        for (_iterator.s(); !(_step = _iterator.n()).done;) {
          var conditionId = _step.value;
          this.$('#hustle-condition--' + conditionId).prop('checked', true).prop('disabled', true);
        }
      } catch (err) {
        _iterator.e(err);
      } finally {
        _iterator.f();
      }
    },
    selectConditions: function selectConditions(e) {
      var $input = this.$(e.target),
          $selectorLabel = this.$el.find('label[for="' + $input.attr('id') + '"]'),
          value = $input.val();
      $selectorLabel.toggleClass('selected');

      if ($input.prop('checked')) {
        this.selectedConditions.push(value);
      } else {
        this.selectedConditions = _.without(this.selectedConditions, value);
      }
    },
    addConditions: function addConditions(e) {
      var me = this,
          $button = this.$(e.target);
      $button.addClass('sui-button-onload');
      this.trigger('conditions:added', {
        groupId: this.opts.groupId,
        conditions: this.selectedConditions
      });
      setTimeout(function () {
        // Hide dialog
        SUI.closeModal();
        $button.removeClass('sui-button-onload');
        me.undelegateEvents();
      }, 500);
    }
  });
});
function _toConsumableArray(arr) { return _arrayWithoutHoles(arr) || _iterableToArray(arr) || _unsupportedIterableToArray(arr) || _nonIterableSpread(); }

function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }

function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }

function _iterableToArray(iter) { if (typeof Symbol !== "undefined" && Symbol.iterator in Object(iter)) return Array.from(iter); }

function _arrayWithoutHoles(arr) { if (Array.isArray(arr)) return _arrayLikeToArray(arr); }

function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) { arr2[i] = arr[i]; } return arr2; }

/* global Chart */
(function ($) {
  'use strict';

  Optin.listingBase = Hustle.View.extend({
    el: '.sui-wrap-hustle',
    logShown: false,
    moduleType: '',
    previewView: null,
    _events: {
      // Modals.
      'click .hustle-create-module': 'openCreateModal',
      'click .hustle-manage-tracking-button': 'openManageTrackingModal',
      'click .hustle-import-module-button': 'openImportModal',
      'click .hustle-upgrade-modal-button': 'openUpgradeModal',
      // Modules' actions.
      'click .hustle-single-module-button-action': 'handleSingleModuleAction',
      'click .hustle-preview-module-button': 'previewModule',
      // Bulk actions.
      'click form.sui-bulk-actions .hustle-bulk-apply-button': 'bulkActionCheck',
      'click #hustle-dialog--delete .hustle-delete': 'bulkActionSend',
      'click #hustle-bulk-action-reset-tracking-confirmation .hustle-delete': 'bulkActionSend',
      // Utilities.
      'click .sui-accordion-item-action .hustle-onload-icon-action': 'addLoadingIconToActionsButton'
    },
    initialize: function initialize(opts) {
      this.events = $.extend(true, {}, this.events, this._events);
      this.delegateEvents();
      this.moduleType = opts.moduleType;
      var newModuleModal = Hustle.get('Modals.New_Module'),
          importModal = Hustle.get('Modals.ImportModule');
      this.newModuleModal = new newModuleModal(this.moduleType, this.getPreviewView());
      this.ImportModal = new importModal(); // Why this doesn't work when added in events

      $('.sui-accordion-item-header').on('click', $.proxy(this.openTrackingChart, this)); // Open the tracking chart when the class is present. Used when coming from 'view tracking' in Dashboard.

      if ($('.hustle-display-chart').length) {
        this.openTrackingChart($('.hustle-display-chart'));
      }

      this.doActionsBasedOnUrl();
    },
    doActionsBasedOnUrl: function doActionsBasedOnUrl() {
      // Display the "Create module" dialog.
      if ('true' === Module.Utils.getUrlParam('create-module')) {
        setTimeout(function () {
          $('.hustle-create-module').trigger('click');
        }, 100);
      } // Display "Upgrade modal".


      if ('true' === Module.Utils.getUrlParam('requires-pro')) {
        var self = this;
        setTimeout(function () {
          return self.openUpgradeModal();
        }, 100);
      } // Display notice based on URL parameters.


      if (Module.Utils.getUrlParam('show-notice')) {
        var status = 'success' === Module.Utils.getUrlParam('show-notice') ? 'success' : 'error',
            notice = Module.Utils.getUrlParam('notice'),
            message = notice && 'undefined' !== optinVars.messages[notice] ? optinVars.messages[notice] : Module.Utils.getUrlParam('notice-message'),
            closeTimeParam = Module.Utils.getUrlParam('notice-close', null),
            closeTime = 'false' === closeTimeParam ? false : closeTimeParam;

        if ('undefined' !== typeof message && message.length) {
          Module.Notification.open(status, message, closeTime);
        }
      } // View module stats.


      var viewId = Module.Utils.getUrlParam('view-stats');

      if (viewId) {
        var $header = $('.hustle-list .sui-accordion-item-header[data-id="' + viewId + '"]');
        $header.trigger('click');
        $('html, body').animate({
          scrollTop: $header.closest('.sui-accordion-item').offset().top - 40
        }, 1000);
      }
    },
    handleSingleModuleAction: function handleSingleModuleAction(e) {
      this.addLoadingIcon(e);
      Module.handleActions.initAction(e, 'listing', this);
    },
    previewModule: function previewModule(e) {
      e.preventDefault();
      var $button = $(e.currentTarget);
      this.getPreviewView().open($button.data('id'), $button.data('type'), $button, {
        module_name: $button.data('name')
      });
    },
    getPreviewView: function getPreviewView() {
      if (!this.previewView) {
        var previewView = Hustle.get('Modals.Preview');
        this.previewView = new previewView();
      }

      return this.previewView;
    },
    openTrackingChart: function openTrackingChart(e) {
      var flexHeader = '';

      if (e.target) {
        if ($(e.target).closest('.sui-accordion-item-action').length) {
          return true;
        }

        e.preventDefault();
        e.stopPropagation();
        flexHeader = $(e.currentTarget);
      } else {
        flexHeader = e;
      }

      var self = this,
          flexItem = flexHeader.parent();
      var flexChart = flexItem.find('.sui-chartjs-animated');

      if (flexItem.hasClass('sui-accordion-item--disabled')) {
        flexItem.removeClass('sui-accordion-item--open');
      } else if (flexItem.hasClass('sui-accordion-item--open')) {
        flexItem.removeClass('sui-accordion-item--open');
      } else {
        flexItem.addClass('sui-accordion-item--open');
      }

      flexItem.find('.sui-accordion-item-data').addClass('sui-onload');
      flexChart.removeClass('sui-chartjs-loaded');

      if (flexItem.hasClass('sui-accordion-item--open')) {
        var id = flexHeader.data('id'),
            nonce = flexHeader.data('nonce'),
            data = {
          id: id,
          _ajax_nonce: nonce,
          action: 'hustle_tracking_data'
        };
        $.ajax({
          url: ajaxurl,
          type: 'POST',
          data: data,
          success: function success(resp) {
            if (resp.success && resp.data) {
              flexItem.find('.sui-accordion-item-body').html(resp.data.html);
              self.trackingChart.init(flexItem, resp.data.charts_data);
              flexChart = flexItem.find('.sui-chartjs-animated'); // Init tabs

              SUI.suiTabs();
            }

            flexItem.find('.sui-accordion-item-data').removeClass('sui-onload');
            flexChart.addClass('sui-chartjs-loaded');
          },
          error: function error() {
            flexItem.find('.sui-accordion-item-data').removeClass('sui-onload');
            flexChart.addClass('sui-chartjs-loaded');
          }
        });
      }
    },
    getChecked: function getChecked(type) {
      var query = '.sui-wrap-hustle .sui-accordion-item-title input[type=checkbox]';

      if ('checked' === type) {
        query += ':checked';
      }

      return $(query);
    },
    bulkActionCheck: function bulkActionCheck(e) {
      var $this = $(e.target),
          value = $this.closest('.hustle-bulk-actions-container').find('select[name="hustle_action"] option:selected').val(),
          //$( 'select option:selected', $this.closest( '.sui-box' ) ).val(),
      elements = this.getChecked('checked');

      if (0 === elements.length || 'undefined' === value) {
        return false;
      }

      if ('delete' === value) {
        var data = {
          actionClass: 'hustle-delete',
          action: 'delete',
          title: $this.data('delete-title'),
          description: $this.data('delete-description')
        };
        Module.deleteModal.open(data, $this[0]);
        return false;
      } else if ('reset-tracking' === value) {
        var _data = {
          actionClass: 'hustle-delete',
          action: 'reset-tracking',
          title: $this.data('reset-title'),
          description: $this.data('reset-description')
        };
        Module.deleteModal.open(_data, $this[0]);
        return false;
      }

      this.bulkActionSend(e, value);
    },
    bulkActionSend: function bulkActionSend(e, action) {
      e.preventDefault();
      this.addLoadingIcon(e);
      var value = action ? action : $(e.target).data('hustle-action'),
          elements = this.getChecked('checked');

      if (0 === elements.length) {
        return false;
      }

      var ids = [];
      $.each(elements, function () {
        ids.push($(this).val());
      });
      var button = $('.sui-bulk-actions .hustle-bulk-apply-button'),
          data = {
        ids: ids,
        hustle: value,
        type: button.data('type'),
        _ajax_nonce: button.data('nonce'),
        action: 'hustle_listing_bulk'
      };
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data,
        success: function success(resp) {
          if (resp.success) {
            location.reload();
          } else {
            SUI.closeModal(); //show error notice
          }
        }
      });
    },
    addLoadingIcon: function addLoadingIcon(e) {
      var $button = $(e.currentTarget);

      if ($button.hasClass('sui-button')) {
        $button.addClass('sui-button-onload');
      }
    },
    addLoadingIconToActionsButton: function addLoadingIconToActionsButton(e) {
      var $actionButton = $(e.currentTarget),
          $mainButton = $actionButton.closest('.sui-accordion-item-action').find('.sui-dropdown-anchor');
      $mainButton.addClass('sui-button-onload');
    },
    // ===================================
    // Modals
    // ===================================
    openCreateModal: function openCreateModal(e) {
      if (false === $(e.currentTarget).data('enabled')) {
        this.openUpgradeModal();
      } else {
        this.newModuleModal.open();
      }
    },
    openUpgradeModal: function openUpgradeModal(e) {
      var focusOnClose = this.$('#hustle-create-new-module')[0];

      if (e) {
        e.preventDefault();
        e.stopPropagation();
        focusOnClose = e.currentTarget;
      }

      $('.sui-button-onload').removeClass('sui-button-onload');

      if (!$('#hustle-modal--upgrade-to-pro').length) {
        return;
      }

      SUI.openModal('hustle-modal--upgrade-to-pro', focusOnClose, 'hustle-button--upgrade-to-pro', true);
    },
    openImportModal: function openImportModal(e) {
      var $this = $(e.currentTarget);

      if (false === $this.data('enabled')) {
        this.openUpgradeModal();
      } else {
        this.ImportModal.open(e);
      }
    },

    /**
     * The "are you sure?" modal from before resetting the tracking data of modules.
     *
     * @since 4.0.0
     * @param {Event} e Event.
     */
    openManageTrackingModal: function openManageTrackingModal(e) {
      var template = Optin.template('hustle-manage-tracking-form-tpl'),
          $modal = $('#hustle-dialog--manage-tracking'),
          $button = $(e.currentTarget),
          moduleId = $button.data('module-id'),
          data = {
        //moduleID: $button.data( 'module-id' ),
        enabledTrackings: $button.data('tracking-types').split(',')
      };
      $modal.find('#hustle-manage-tracking-form-container').html(template(data));
      $modal.find('#hustle-button-toggle-tracking-types').data('module-id', moduleId);
      SUI.openModal('hustle-dialog--manage-tracking', $button, 'hustle-module-tracking--inline', true);
    },
    // ===================================
    // Tracking charts
    // ===================================

    /**
     * Renders the module's charts in the listing pages.
     * It also handles the view when the 'conversions type' select changes.
     *
     * @since 4.0.4
     */
    trackingChart: {
      chartsData: {},
      theCharts: {},
      init: function init($container, chartsData) {
        var _this = this;

        $container.find('select.hustle-conversion-type').each(function (i, el) {
          SUI.select.init($(el));
          $(el).on('change.select2', function (e) {
            return _this.conversionTypeChanged(e, $container);
          });
        });
        this.chartsData = chartsData;
        Object.values(chartsData).forEach(function (chart) {
          return _this.updateChart(chart);
        });
      },
      conversionTypeChanged: function conversionTypeChanged(e, $container) {
        var $select = $(e.currentTarget),
            conversionType = $select.val(),
            moduleSubType = $select.data('moduleType'),
            subTypeChart = this.chartsData[moduleSubType],
            $conversionsCount = $container.find(".hustle-tracking-".concat(moduleSubType, "-conversions-count")),
            $conversionsRate = $container.find(".hustle-tracking-".concat(moduleSubType, "-conversions-rate")); // Update the number for the conversions count and conversion rate at the top of the chart.

        $conversionsCount.text(subTypeChart[conversionType].conversions_count);
        $conversionsRate.text(subTypeChart[conversionType].conversion_rate + '%');
        this.updateChart(subTypeChart, conversionType, false);
      },
      updateChart: function updateChart(chart) {
        var conversionType = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'all';
        var render = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : true;
        var views = chart.views,
            submissions = chart[conversionType].conversions,
            datasets = [{
          label: 'Submissions',
          data: submissions,
          backgroundColor: ['#E1F6FF'],
          borderColor: ['#17A8E3'],
          borderWidth: 2,
          pointRadius: 0,
          pointHitRadius: 20,
          pointHoverRadius: 5,
          pointHoverBorderColor: '#17A8E3',
          pointHoverBackgroundColor: '#17A8E3'
        }, {
          label: 'Views',
          data: views,
          backgroundColor: ['#F8F8F8'],
          borderColor: ['#DDDDDD'],
          borderWidth: 2,
          pointRadius: 0,
          pointHitRadius: 20,
          pointHoverRadius: 5,
          pointHoverBorderColor: '#DDDDDD',
          pointHoverBackgroundColor: '#DDDDDD'
        }]; // The chart was already created. Update it.

        if ('undefined' !== typeof this.theCharts[chart.id]) {
          // The container has been re-rendered, so render the chart again.
          if (render) {
            this.theCharts[chart.id].destroy();
            this.createNewChart(chart, datasets);
          } else {
            // Just update the chart otherwise.
            this.theCharts[chart.id].data.datasets = datasets;
            this.theCharts[chart.id].update();
          }
        } else {
          this.createNewChart(chart, datasets);
        }
      },
      createNewChart: function createNewChart(chart, datasets) {
        var yAxesHeight = Math.max.apply(Math, _toConsumableArray(chart.views)) + 2;
        var chartContainer = document.getElementById(chart.id);

        if (Math.max.apply(Math, _toConsumableArray(chart.views)) < Math.max.apply(Math, _toConsumableArray(chart.conversions))) {
          yAxesHeight = Math.max.apply(Math, _toConsumableArray(chart.conversions)) + 2;
        }

        if (!chartContainer) {
          return;
        }

        var days = chart.days,
            chartData = {
          labels: days,
          datasets: datasets
        };
        var chartOptions = {
          maintainAspectRatio: false,
          legend: {
            display: false
          },
          scales: {
            xAxes: [{
              display: false,
              gridLines: {
                color: 'rgba(0, 0, 0, 0)'
              }
            }],
            yAxes: [{
              display: false,
              gridLines: {
                color: 'rgba(0, 0, 0, 0)'
              },
              ticks: {
                beginAtZero: false,
                min: 0,
                max: yAxesHeight,
                stepSize: 1
              }
            }]
          },
          elements: {
            line: {
              tension: 0
            },
            point: {
              radius: 0.5
            }
          },
          tooltips: {
            custom: function custom(tooltip) {
              if (!tooltip) {
                return;
              } // Disable displaying the color box


              tooltip.displayColors = false;
            },
            callbacks: {
              title: function title(tooltipItem) {
                if (0 === tooltipItem[0].datasetIndex) {
                  return optinVars.labels.submissions.replace('%d', tooltipItem[0].yLabel); // + ' Submissions';
                } else if (1 === tooltipItem[0].datasetIndex) {
                  return optinVars.labels.views.replace('%d', tooltipItem[0].yLabel); //+ ' Views';
                }
              },
              label: function label(tooltipItem) {
                return tooltipItem.xLabel;
              },
              // Set label text color
              labelTextColor: function labelTextColor() {
                return '#AAAAAA';
              }
            }
          }
        };
        this.theCharts[chart.id] = new Chart(chartContainer, {
          type: 'line',
          fill: 'start',
          data: chartData,
          options: chartOptions
        });
      }
    }
  });
})(jQuery);
Hustle.define('Modals.New_Module', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-dialog--create-new-module',
    previewView: null,
    moduleType: '',
    moduleName: false,
    moduleMode: 'optin',
    moduleTemplate: 'none',
    $moveForwardButton: null,
    data: {},
    mainDialogLabelId: 'hustle-create-new-module-dialog-label',
    mainDialogDescriptionId: 'hustle-create-new-module-dialog-description',
    events: {
      'keydown input[name="name"]': 'nameChanged',
      'click #hustle-create-module': 'createModule',
      'change input[name="mode"]': 'modeChanged',
      'click #hustle-go-to-templates-button': 'goToTemplatesStep',
      'click .hustle-template-select-button': 'createNonSshare',
      'click .hustle-template-preview-button': 'previewTemplate',
      'click .hustle-modal-go-back': 'goToStepOne'
    },
    initialize: function initialize(moduleType, previewView) {
      this.moduleType = moduleType;
      this.previewView = previewView;
      var nextButtonSelector = 'social_sharing' !== this.moduleType ? '#hustle-go-to-templates-button' : '#hustle-create-module';
      this.$moveForwardButton = this.$(nextButtonSelector);
    },
    open: function open() {
      SUI.openModal('hustle-dialog--create-new-module', 'hustle-create-new-module', 'hustle-module-name');

      if ('social_sharing' !== this.moduleType) {
        this.goToStepOne();
      }
    },
    nameChanged: function nameChanged(e) {
      var _this = this;

      setTimeout(function () {
        _this.$('.sui-error-message').hide();

        var value = $(e.currentTarget).val().trim();

        if (0 === value.length) {
          _this.moduleName = false;

          _this.$moveForwardButton.prop('disabled', true);

          _this.$('#error-empty-name').closest('.sui-form-field').addClass('sui-form-field-error');

          _this.$('#error-empty-name').show();
        } else {
          _this.moduleName = value;

          _this.$moveForwardButton.prop('disabled', false);

          _this.$('#error-empty-name').closest('.sui-form-field').removeClass('sui-form-field-error');

          _this.$('#error-empty-name').hide();
        }
      }, 300);
    },
    modeChanged: function modeChanged(e) {
      var value = $(e.currentTarget).val();
      this.moduleMode = value;
    },
    goToStepOne: function goToStepOne(e) {
      var animation = e ? 'back' : null;
      this.$el.attr('aria-labelledby', this.mainDialogLabelId);
      this.$el.attr('aria-describedby', this.mainDialogDescriptionId);
      SUI.slideModal('hustle-create-new-module-step-1', 'hustle-module-name', animation);
    },
    goToTemplatesStep: function goToTemplatesStep(e) {
      e.preventDefault();

      if (this.isNameValid() && this.isModeValid()) {
        var stepId = 'optin' === this.moduleMode ? 'optin-templates' : 'informational-templates',
            stepLabelId = "hustle-create-new-module-dialog-step-".concat(stepId, "-label"),
            stepDescriptionId = "hustle-create-new-module-dialog-step-".concat(stepId, "-description");
        this.$el.attr('aria-labelledby', stepLabelId);
        this.$el.attr('aria-describedby', stepDescriptionId);
        SUI.slideModal("hustle-create-new-module-step-".concat(stepId), this.$el.find("#hustle-create-new-module-step-".concat(stepId, " .hustle-template-option--none"))[0], 'next');
      }
    },
    isNameValid: function isNameValid() {
      return false !== this.moduleName;
    },
    isModeValid: function isModeValid() {
      return 'optin' === this.moduleMode || 'informational' === this.moduleMode;
    },
    createNonSshare: function createNonSshare(e) {
      var selectedTemplate = $(e.currentTarget).data('template');
      this.moduleTemplate = selectedTemplate;
      this.createModule(e);
    },
    createModule: function createModule(e) {
      var nonce = this.$el.data('nonce'),
          errorMessage = this.$el.data('error-message'),
          $button = $(e.currentTarget),
          data = {
        module_name: this.moduleName,
        module_type: this.moduleType,
        module_mode: this.moduleMode,
        module_template: this.moduleTemplate,
        action: 'hustle_create_new_module',
        _ajax_nonce: nonce
      };
      $button.addClass('sui-button-onload');
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data
      }).done(function (res) {
        // Go to the wizard of this type of module on success, or listing page if limits were reached.
        if (res && res.data && res.data.redirect_url) {
          window.location.replace(res.data.redirect_url);
        } else {
          $button.removeClass('sui-button-onload');
          Module.Notification.open('error', errorMessage, false);
        }
      }).fail(function () {
        $button.removeClass('sui-button-onload');
        Module.Notification.open('error', errorMessage, false);
      });
    },
    previewTemplate: function previewTemplate(e) {
      var $button = $(e.currentTarget);
      this.previewView.open(0, $button.data('module-type'), $button, {
        module_name: $button.data('name'),
        module_type: $button.data('module-type'),
        template_name: $button.data('template'),
        template_mode: $button.data('module-mode')
      });
    }
  });
});
Hustle.define('Modals.ImportModule', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-dialog--import',
    events: {
      'change #hustle-import-file-input': 'selectUploadFile',
      'click .sui-upload-file': 'changeFile',
      'click .sui-upload-file button': 'resetUploadFile',
      'click .hustle-import-check-all-checkbox': 'checkAll',
      'change .hustle-module-meta-checkbox': 'uncheckAllOption'
    },
    initialize: function initialize() {},
    open: function open(e) {
      var $this = $(e.currentTarget),
          moduleId = $this.data('module-id'),
          template = Optin.template('hustle-import-modal-options-tpl'),
          $importDialog = $('#hustle-dialog--import'),
          $submitButton = $importDialog.find('#hustle-import-module-submit-button'),
          isNew = 'undefined' === typeof moduleId,
          templateData = {
        isNew: isNew,
        isOptin: 'optin' === $this.data('module-mode') // Always "false" when importing into a new module.

      };
      $importDialog.find('#hustle-import-modal-options').html(template(templateData));

      if (isNew) {
        $submitButton.removeAttr('data-module-id'); // Bind the tabs again with their SUI actions.
        // Only the modal for importing a new module has tabs.

        SUI.tabs();
        $importDialog.find('.sui-tab-item').on('click', function () {
          var $tab = $(this),
              $radio = $('#' + $tab.data('label-for'));
          $radio.click();
        });
      } else {
        $submitButton.attr('data-module-id', moduleId);
      }

      SUI.openModal('hustle-dialog--import', e.currentTarget, 'hustle-import-file-input', true);
    },
    selectUploadFile: function selectUploadFile(e) {
      e.preventDefault();
      var $this = $(e.target),
          value = $this.val().replace(/C:\\fakepath\\/i, ''); // Hide previous error.

      SUI.closeNotice('hustle-dialog--import-error-notice');

      if (value) {
        $('.sui-upload-file span:first').text(value);
        $('.sui-upload').addClass('sui-has_file');
        $('#hustle-import-module-submit-button').prop('disabled', false);
      } else {
        $('.sui-upload').removeClass('sui-has_file');
        $('.sui-upload-file span:first').text('');
        $('#hustle-import-module-submit-button').prop('disabled', true);
      }
    },
    resetUploadFile: function resetUploadFile(e) {
      e.stopPropagation();
      $('#hustle-import-file-input').val('').trigger('change');
    },
    changeFile: function changeFile() {
      $('#hustle-import-file-input').trigger('click');
    },
    checkAll: function checkAll(e) {
      var $this = $(e.currentTarget),
          value = $this.is(':checked'),
          $container = $this.closest('.hui-inputs-list'),
          $checkboxes = $container.find('input.hustle-module-meta-checkbox:not(.hustle-import-check-all-checkbox)');
      $checkboxes.prop('checked', value);
    },
    uncheckAllOption: function uncheckAllOption(e) {
      var $this = $(e.currentTarget),
          $container = $this.closest('.hui-inputs-list'),
          $allCheckbox = $container.find('.hustle-import-check-all-checkbox'),
          isAllChecked = $allCheckbox.is(':checked');

      if (!isAllChecked) {
        return;
      }

      $allCheckbox.prop('checked', false);
    }
  });
});
function _toConsumableArray(arr) { return _arrayWithoutHoles(arr) || _iterableToArray(arr) || _unsupportedIterableToArray(arr) || _nonIterableSpread(); }

function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }

function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }

function _iterableToArray(iter) { if (typeof Symbol !== "undefined" && Symbol.iterator in Object(iter)) return Array.from(iter); }

function _arrayWithoutHoles(arr) { if (Array.isArray(arr)) return _arrayLikeToArray(arr); }

function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) { arr2[i] = arr[i]; } return arr2; }

Hustle.define('Mixins.Model_Updater', function ($) {
  'use strict';

  return {
    initMix: function initMix() {
      this.events = _.extend({}, this.events, this._events);
      this.delegateEvents();
    },
    _events: {
      'change textarea': '_updateText',
      'change input[type="text"]': '_updateText',
      'change input[type="url"]': '_updateText',
      'change input[type="hidden"]': '_updateText',
      'change input[type="number"]': '_updateText',
      'change input[type="checkbox"]': '_updateCheckbox',
      'change input[type=radio]': '_updateRadios',
      'change select': '_updateSelect'
    },
    _updateText: function _updateText(e) {
      var $this = $(e.target),
          attr = $this.data('attribute'),
          model = this[$this.data('model') || 'model'],
          opts = _.isTrue($this.data('silent')) ? {
        silent: true
      } : {};

      if (model && attr) {
        e.stopPropagation();
        model.set.call(model, attr, e.target.value, opts);
      }
    },
    _updateCheckbox: function _updateCheckbox(e) {
      var $this = $(e.target),
          attr = $this.data('attribute'),
          value = $this.val(),
          model = this[$this.data('model') || 'model'],
          opts = _.isTrue($this.data('silent')) ? {
        silent: true
      } : {};

      if (model && attr) {
        e.stopPropagation(); // If the checkboxes values should behave as an array, instead of as an on/off toggle.

        if ('on' !== value) {
          var newValue = [];
          var current = model.get.call(model, attr);

          if ($this.is(':checked')) {
            newValue = _toConsumableArray(current);
            newValue.push(value);
          } else {
            newValue = _.without(current, value);
          }

          model.set.call(model, attr, newValue, opts);
        } else {
          model.set.call(model, attr, $this.is(':checked') ? '1' : '0', opts);
        }
      }
    },
    _updateRadios: function _updateRadios(e) {
      var $this = $(e.target),
          attribute = $this.data('attribute'),
          model = this[$this.data('model') || 'model'],
          opts = _.isTrue($this.data('silent')) ? {
        silent: true
      } : {};

      if (model && attribute) {
        e.stopPropagation();
        model.set.call(model, attribute, e.target.value, opts);
      }
    },
    _updateSelect: function _updateSelect(e) {
      var $this = $(e.target),
          attr = $this.data('attribute'),
          model = this[$this.data('model') || 'model'],
          opts = _.isTrue($this.data('silent')) ? {
        silent: true
      } : {};

      if (model && attr) {
        e.stopPropagation();
        model.set.call(model, attr, $this.val(), opts);
      }
    }
  };
});
function _createForOfIteratorHelper(o, allowArrayLike) { var it; if (typeof Symbol === "undefined" || o[Symbol.iterator] == null) { if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || allowArrayLike && o && typeof o.length === "number") { if (it) o = it; var i = 0; var F = function F() {}; return { s: F, n: function n() { if (i >= o.length) return { done: true }; return { done: false, value: o[i++] }; }, e: function e(_e) { throw _e; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var normalCompletion = true, didErr = false, err; return { s: function s() { it = o[Symbol.iterator](); }, n: function n() { var step = it.next(); normalCompletion = step.done; return step; }, e: function e(_e2) { didErr = true; err = _e2; }, f: function f() { try { if (!normalCompletion && it.return != null) it.return(); } finally { if (didErr) throw err; } } }; }

function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }

function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) { arr2[i] = arr[i]; } return arr2; }

/* global moment, sprintf */
Hustle.define('Mixins.Module_Settings', function ($) {
  'use strict';

  return _.extend({}, Hustle.get('Mixins.Model_Updater'), {
    el: '#hustle-wizard-behaviour',
    events: {},
    triggersModel: null,
    init: function init(opts) {
      var self = this,
          Model = opts.BaseModel.extend({
        defaults: {},
        initialize: function initialize(data) {
          _.extend(this, data);

          var Triggers = Hustle.get('Models.Trigger');

          if (!(this.get('triggers') instanceof Backbone.Model)) {
            this.set('triggers', new Triggers(this.triggers), {
              silent: true
            });
            self.triggersModel = this.get('triggers');
          }
        }
      });
      this.model = new Model(optinVars.current.settings || {});
      this.moduleType = optinVars.current.data.module_type;
      var EditScheduleModalView = Hustle.get('Modals.EditSchedule');
      this.editScheduleView = new EditScheduleModalView({
        model: this.model
      });
      this.listenTo(this.model, 'change', this.viewChanged);

      if ('embedded' !== this.moduleType) {
        this.listenTo(this.model.get('triggers'), 'change', this.triggersViewChanged);
      } // Called just to trigger the "view.rendered" action.


      this.render();
    },
    render: function render() {
      this.renderScheduleSection();
      this.editScheduleView.on('schedule:updated', $.proxy(this.renderScheduleSection, this)); // Order matters. Tags will show up in disabled accordions if calling 'toggleTriggerAccordionsDisabled' first.

      this.initTriggerAccordionsTag();
      this.toggleTriggerAccordionsDisabled();
    },
    renderScheduleSection: function renderScheduleSection() {
      var _this = this;

      var template = Optin.template('hustle-schedule-row-tpl'),
          $container = $('#hustle-schedule-row'),
          scheduleSettings = this.model.get('schedule'),
          data = Object.assign({}, scheduleSettings),
          strings = {
        startDate: '',
        startTime: '',
        endDate: '',
        endTime: '',
        activeDays: '',
        activeTime: ''
      };
      var hasFinished = false;
      data.is_schedule = this.model.get('is_schedule'); // eslint-disable-line camelcase
      // Here we'll build the strings dependent on the selected settings. Skip if scheduling is disabled.

      if (data.is_schedule) {
        // Translated months and 'AM/PM' strings.
        var months = Object.assign({}, optinVars.schedule.months),
            meridiem = optinVars.schedule.meridiem; // Schedule start string. Skip if disabled.

        if ('0' === data.not_schedule_start) {
          var stringDate = data.start_date.split('/'),
              month = months[stringDate[0] - 1],
              ampm = meridiem[data.start_meridiem_offset];
          strings.startDate = "".concat(stringDate[1], " ").concat(month, " ").concat(stringDate[2]);
          strings.startTime = "(".concat(data.start_hour, ":").concat(data.start_minute, " ").concat(ampm, ")");
        } // Schedule end string. Skip if disabled.


        if ('0' === data.not_schedule_end) {
          var _stringDate = data.end_date.split('/'),
              _month = months[_stringDate[0] - 1],
              _ampm = meridiem[data.end_meridiem_offset];

          strings.endDate = "".concat(_stringDate[1], " ").concat(_month, " ").concat(_stringDate[2]);
          strings.endTime = "(".concat(data.end_hour, ":").concat(data.end_minute, " ").concat(_ampm, ")");
          hasFinished = this.isScheduleFinished(data);
        } // Selected weekdays string. Skip if 'every day' is selected.


        if ('week_days' === data.active_days) {
          var weekDays = optinVars.schedule.week_days,
              days = data.week_days.map(function (day) {
            return weekDays[day].toUpperCase();
          });
          strings.activeDays = days.join(', ');
        } // Per day start and end string. Skip if 'during all day' is enabled.


        if ('0' === data.is_active_all_day) {
          var startAmpm = meridiem[data.day_start_meridiem_offset],
              endAmpm = meridiem[data.day_end_meridiem_offset],
              dayStart = "".concat(data.day_start_hour, ":").concat(data.day_start_minute, " ").concat(startAmpm),
              dayEnd = "".concat(data.day_end_hour, ":").concat(data.day_end_minute, " ").concat(endAmpm);
          strings.activeTime = dayStart + ' - ' + dayEnd;
        }
      }

      data.strings = strings;
      data.hasFinished = hasFinished;
      $container.html(template(data));
      $container.find('.hustle-button-open-schedule-dialog').on('click', function () {
        return _this.editScheduleView.open();
      });
    },
    isScheduleFinished: function isScheduleFinished(settings) {
      var currentTime = new Date().getTime();
      var timeToUse = settings.time_to_use,
          date = settings.end_date,
          hour = settings.end_hour,
          minute = settings.end_minute,
          ampm = settings.end_meridiem_offset,
          dateString = "".concat(date, " ").concat(hour, ":").concat(minute, " ").concat(ampm);
      var endTimestamp = false,
          utcOffset = false;

      if ('server' === timeToUse) {
        utcOffset = optinVars.schedule.wp_gmt_offset;
      } else {
        var customTimezone = settings.custom_timezone; // It's using a manual UTC offset.

        if (customTimezone.includes('UTC')) {
          var selectedOffset = customTimezone.replace('UTC', ''); // There's a timezone with the value "UTC".

          utcOffset = selectedOffset.length ? parseFloat(selectedOffset) : 0;
        } else {
          var endMoment = moment.tz(dateString, 'MM/DD/YYYY hh:mm aa', customTimezone);
          endTimestamp = endMoment.format('x');
        }
      } // Calculate the timestamp with the manual offset.


      if (false === endTimestamp && false !== utcOffset) {
        var offset = 60 * utcOffset,
            sign = 0 < offset ? '+' : '-',
            abs = Math.abs(offset),
            formattedOffset = sprintf('%s%02d:%02d', sign, abs / 60, abs % 60);

        var _endMoment = moment.parseZone(dateString + ' ' + formattedOffset, 'MM/DD/YYYY hh:mm a Z');

        endTimestamp = _endMoment.format('x');
      } // Check if the end time already passed.


      if (currentTime > endTimestamp) {
        return true;
      }

      return false;
    },
    viewChanged: function viewChanged(model) {
      var changed = model.changed;

      if ('on_submit' in changed) {
        var $toggleDiv = this.$('#hustle-on-submit-delay-wrapper');

        if ($toggleDiv.length) {
          if ('nothing' !== changed.on_submit) {
            $toggleDiv.removeClass('sui-hidden');
          } else {
            $toggleDiv.addClass('sui-hidden');
          }
        }
      }
    },
    triggersViewChanged: function triggersViewChanged(model) {
      var changed = model.changed,
          changedKey = Object.keys(changed)[0];

      if ('trigger' === changedKey) {
        this.toggleTriggerAccordionsDisabled();
      } else {
        var $changedInput = this.$("[name=\"trigger_".concat(changedKey, "\"]")); // TODO: standardize this. Some inputs have "trigger_" prefixed to their key.
        // The sidetabs have "triggers.".

        if (!$changedInput.length) {
          $changedInput = this.$("[name=\"triggers.".concat(changedKey, "\"]"));
        }

        this.updateTriggerTag($changedInput.closest('.hustle-trigger-accordion-item'));

        if ('on_scroll' === changedKey) {
          var scrollPast = this.triggersModel.get('on_scroll'),
              hide = 'scrolled' === scrollPast ? 'selector' : 'scrolled',
              show = 'scrolled' === scrollPast ? 'scrolled' : 'selector';
          this.$("#hustle-on-scroll--".concat(hide, "-toggle-wrapper")).addClass('sui-hidden');
          this.$("#hustle-on-scroll--".concat(show, "-toggle-wrapper")).removeClass('sui-hidden');
        }
      }
    },
    toggleTriggerAccordionsDisabled: function toggleTriggerAccordionsDisabled() {
      var triggerAccordions = this.$('.hustle-trigger-accordion-item'),
          selectedTriggers = this.triggersModel.get('trigger');

      var toggleDisabled = function toggleDisabled($accordion) {
        var accordionTrigger = $accordion.data('trigger'),
            $optionTag = $accordion.find('.hustle-trigger-tag'),
            isActive = selectedTriggers.includes(accordionTrigger);

        if (isActive) {
          $optionTag.show();
          $accordion.removeClass('sui-accordion-item--disabled');
        } else {
          $optionTag.hide();
          $accordion.addClass('sui-accordion-item--disabled');
        }
      };

      var _iterator = _createForOfIteratorHelper(triggerAccordions),
          _step;

      try {
        for (_iterator.s(); !(_step = _iterator.n()).done;) {
          var accordion = _step.value;
          toggleDisabled($(accordion));
        }
      } catch (err) {
        _iterator.e(err);
      } finally {
        _iterator.f();
      }
    },
    initTriggerAccordionsTag: function initTriggerAccordionsTag() {
      var triggerAccordions = this.$('.hustle-trigger-accordion-item');

      var _iterator2 = _createForOfIteratorHelper(triggerAccordions),
          _step2;

      try {
        for (_iterator2.s(); !(_step2 = _iterator2.n()).done;) {
          var accordion = _step2.value;
          this.updateTriggerTag($(accordion));
        }
      } catch (err) {
        _iterator2.e(err);
      } finally {
        _iterator2.f();
      }
    },
    updateTriggerTag: function updateTriggerTag($triggerAccordion) {
      var trigger = $triggerAccordion.data('trigger'),
          $accordionTitle = $triggerAccordion.find('.sui-accordion-item-title'),
          $tag = $triggerAccordion.find('.hustle-trigger-tag');

      if ($tag.length) {
        $tag.remove();
      }

      var tagTextArray = this.getTriggerTagText(trigger);

      var _iterator3 = _createForOfIteratorHelper(tagTextArray),
          _step3;

      try {
        for (_iterator3.s(); !(_step3 = _iterator3.n()).done;) {
          var text = _step3.value;

          if (text.trim().length) {
            var newTag = "<span class=\"sui-tag hustle-trigger-tag\">".concat(text, "</span>");
            $accordionTitle.append(newTag);
          }
        }
      } catch (err) {
        _iterator3.e(err);
      } finally {
        _iterator3.f();
      }
    },
    getTriggerTagText: function getTriggerTagText(trigger) {
      var tagText = [];

      if ('scroll' === trigger) {
        tagText = this.getTriggerTagTextForScroll();
      } else if ('click' === trigger) {
        tagText = this.getTriggerTagTextForClick();
      } else {
        tagText = this.getTriggerTagTextForDelays(trigger);
      }

      return tagText;
    },
    getTriggerTagTextForScroll: function getTriggerTagTextForScroll() {
      var scrollPast = this.triggersModel.get('on_scroll');
      var selected, tagBase;

      if ('selector' === scrollPast) {
        selected = _.escape(this.triggersModel.get('on_scroll_css_selector'));
        tagBase = optinVars.triggers.scroll_element_tag;
      } else {
        selected = this.triggersModel.get('on_scroll_page_percent');
        tagBase = optinVars.triggers.scroll_percentage_tag;
      }

      var text = tagBase.replace('{value}', selected),
          textArray = [text];
      return textArray;
    },
    getTriggerTagTextForClick: function getTriggerTagTextForClick() {
      var textArray = [],
          isElementEnabled = '1' === this.triggersModel.get('enable_on_click_element'),
          isShortcodeEnabled = '1' === this.triggersModel.get('enable_on_click_shortcode');

      if (isElementEnabled) {
        var savedElement = _.escape(this.triggersModel.get('on_click_element'));

        textArray.push(savedElement);
      }

      if (isShortcodeEnabled) {
        textArray.push('[wd_hustle]');
      }

      return textArray;
    },
    getTriggerTagTextForDelays: function getTriggerTagTextForDelays(trigger) {
      var triggerDelayOptions = {
        time: {
          time: 'on_time_delay',
          unit: 'on_time_unit'
        },
        exit_intent: {
          time: 'on_exit_intent_delayed_time',
          unit: 'on_exit_intent_delayed_unit'
        },
        adblock: {
          time: 'on_adblock_delay',
          unit: 'on_adblock_delay_unit'
        }
      },
          tagOptions = triggerDelayOptions[trigger];
      var selectedTime = this.triggersModel.get(tagOptions.time);
      var text = optinVars.triggers.immediately_tag;

      if ('0' !== selectedTime) {
        var selectedUnit = this.triggersModel.get(tagOptions.unit),
            translatedUnit = optinVars.triggers[selectedUnit],
            delayTagBase = optinVars.triggers.delayed_tag;
        text = delayTagBase.replace('{time}', selectedTime).replace('{unit}', translatedUnit);
      }

      var textArray = [text];
      return textArray;
    }
  });
});
Hustle.define('Mixins.Module_Content', function () {
  'use strict';

  return _.extend({}, Hustle.get('Mixins.Model_Updater'), {
    el: '#hustle-wizard-content',
    events: {},
    init: function init(opts) {
      this.model = new opts.BaseModel(optinVars.current.content || {});
      this.moduleType = optinVars.current.data.module_type;
      this.listenTo(this.model, 'change', this.modelUpdated);
      this.render();
    },
    render: function render() {
      this.initImageUploaders();

      if ('true' === Module.Utils.getUrlParam('new')) {
        Module.Notification.open('success', optinVars.messages.module_created, 10000);
      }
    },
    initImageUploaders: function initImageUploaders() {
      var MediaHolder = Hustle.get('imageUploader'),
          attrsWithImageUpload = ['feature_image', 'background_image'];

      for (var _i = 0, _attrsWithImageUpload = attrsWithImageUpload; _i < _attrsWithImageUpload.length; _i++) {
        var attribute = _attrsWithImageUpload[_i];
        var $wrapper = this.$('#hustle-choose-' + attribute);

        if ($wrapper.length) {
          new MediaHolder({
            el: $wrapper,
            model: this.model,
            attribute: attribute,
            moduleType: this.moduleType
          });
        }
      }
    },

    /**
     * Updates the active container `aria-labelledby` attr so it matches the active button.
     * For accessibility.
     * We should make this behavior reusable. Maybe it should be handled it sui.
     *
     * @since 4.3.0
     */
    updateLabelledbyCtaContent: function updateLabelledbyCtaContent() {
      var selectedLabelForAttr = this.$('input[name="show_cta"]:checked').attr('id'),
          newLabeledBy = this.$("[data-label-for=\"".concat(selectedLabelForAttr, "\"]")).attr('id');
      this.$('#tab-content-cta-button-one').attr('aria-labelledby', newLabeledBy);
    },
    modelUpdated: function modelUpdated(model) {
      var changedKey = Object.keys(model.changed)[0],
          actionToDo = this.getActionOnModelUpdated(changedKey);

      if ('undefined' !== typeof actionToDo) {
        actionToDo(model.changed);
      }

      Hustle.Events.trigger('modules.view.contentUpdate', model.changed);
    },
    getActionOnModelUpdated: function getActionOnModelUpdated(changedKey) {
      var _this = this;

      var functions = {
        show_cta: function show_cta(changed) {
          if ('0' !== changed.show_cta) {
            Module.Utils.showHideDependencyOnSelectChange(_this.$('#hustle-content-cta-options-container'));
          }
        }
      };
      return functions[changedKey];
    }
  });
});
function _createForOfIteratorHelper(o, allowArrayLike) { var it; if (typeof Symbol === "undefined" || o[Symbol.iterator] == null) { if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || allowArrayLike && o && typeof o.length === "number") { if (it) o = it; var i = 0; var F = function F() {}; return { s: F, n: function n() { if (i >= o.length) return { done: true }; return { done: false, value: o[i++] }; }, e: function e(_e) { throw _e; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var normalCompletion = true, didErr = false, err; return { s: function s() { it = o[Symbol.iterator](); }, n: function n() { var step = it.next(); normalCompletion = step.done; return step; }, e: function e(_e2) { didErr = true; err = _e2; }, f: function f() { try { if (!normalCompletion && it.return != null) it.return(); } finally { if (didErr) throw err; } } }; }

function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }

function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) { arr2[i] = arr[i]; } return arr2; }

/* global ace */
Hustle.define('Mixins.Module_Design', function ($) {
  'use strict';

  return _.extend({}, Hustle.get('Mixins.Model_Updater'), {
    el: '#hustle-wizard-appearance',
    cssEditor: false,
    fontFamilies: {},
    fontFamiliesOptions: [],

    /**
     * Keeps track of the updated properties.
     * It allows us to submit only the updated props during the AJAX save
     * and to avoid save issues with max_input_vars set on 1000.
     *
     * @since 4.3.0
     */
    updatedProperties: {},

    /**
     * Keeps track of which elements are shown.
     *
     * @since 4.3.0
     */
    contentPropIsShown: {
      title: true,
      sub_title: true,
      main_content: true,
      feature_image: true,
      background_image: true,
      show_never_see_link: true,
      show_cta: true
    },
    events: {
      'click .hustle-css-stylable': 'insertSelector',
      'click .hustle-reset-settings-block > button': 'resetSettingsBlock',
      'change [data-link-fields]': 'linkFieldsChanged',
      'change [data-linked-fields]': 'linkedFieldsChanged',
      'change .hustle-font-family-select': 'fontFamilyUpdated',
      'change select[name="feature_image_width_option"]': 'updateFeatureImageWidth',
      'click .hustle-button-apply-global-font': 'applyGlobalFontClicked',
      'change .hustle-required-field': 'requiredFieldChanged'
    },
    init: function init(opts) {
      this.model = new opts.BaseModel(optinVars.current.design || {});
      this.beforeRender();
      this.render();
    },
    beforeRender: function beforeRender() {
      var _this = this;

      this.listenTo(this.model, 'change', this.modelUpdated);
      Hustle.Events.on('modules.view.contentUpdate', function (changed) {
        return _this.contentModelUpdated(changed);
      });
      Hustle.Events.on('modules.view.emailsUpdate', function (changed) {
        return _this.emailsModelUpdated(changed);
      });
      Hustle.Events.on('modules.view.integrationsUpdate', function (changed) {
        return _this.integrationsModelUpdate(changed);
      });
      this.$('#hustle-color-palettes-list').on('select2:open', function () {
        return _this.addCreatePalettesLink();
      }); // Initialize wpColorPickers only before using them.

      this.$('#tab-content-customize_colors-custom .sui-accordion-item').on('click', function (e) {
        return _this.initiateColorPickers(e);
      });
      this.$('.hustle-typography-elements-row .sui-accordion-item-header').on('click', function (e) {
        return _this.initiateFontFamilySelectOnAccordionClick(e);
      });
      this.setFontFamilyOptions();
      this.setVisibilityOnRender();
    },
    render: function render() {
      this.toggleDeviceTabs();
      this.toggleCtaButtonsTextAlignment();
      this.setImageAligmentOptions();
      this.toggleFeatureImageSizeSettingRow();
      this.toggleFeatureImageSizeRows();
      this.cssEditor = this.createEditor('hustle_custom_css');
      this.setVanillaThemeVisibility(); // Hide other Options for Mobile Feature Image.

      this.hideOtherOptionsInAcordionItem('feature_image_hide_on_mobile', '1' === this.model.get('feature_image_hide_on_mobile'));
      this.hideOtherOptionsInAcordionItem('feature_image_position', !this.contentPropIsShown.feature_image);

      if (optinVars.current.is_optin) {
        this.setSucccessfulMessageOptionVisibility(optinVars.current.emails);
        this.formFieldsUpdated(optinVars.current.emails);
        this.updateMailchimpRelatedAccordions(optinVars.current.integrations_settings);
      } else {
        this.handleStyleChange();
      }

      var self = this;
      $.each(['title', 'sub_title', 'feature_image', 'background_image', 'show_cta', 'show_never_see_link', 'main_content'], function (index, key) {
        self.updateElementsRow(key);
      });
    },
    // ============================================================
    // Font-family.
    setFontFamilyOptions: function setFontFamilyOptions() {
      var _this2 = this;

      var optionsPromise = this.fetchFontFamilyOptions();
      optionsPromise.done(function (res) {
        _this2.fontFamilies = res.data;
        $.each(_this2.fontFamilies, function (id, data) {
          _this2.fontFamiliesOptions.push({
            id: id,
            text: data.label
          });
        });

        var $globalFontFamilySelect = _this2.$('.hustle-font-family-select[name="global_font_family"]');

        _this2.initiateFontFamilySelects($globalFontFamilySelect, true);

        _this2.toggleCustomFontInput($globalFontFamilySelect);
      });
    },
    fetchFontFamilyOptions: function fetchFontFamilyOptions() {
      var data = {
        action: 'hustle_fetch_font_families',
        _ajax_nonce: optinVars.typography.fetch_nonce
      };
      return $.post({
        url: ajaxurl,
        type: 'post',
        data: data
      });
    },
    initiateFontFamilySelectOnAccordionClick: function initiateFontFamilySelectOnAccordionClick(e) {
      var self = this;
      $(e.currentTarget).siblings('.sui-accordion-item-body').find('.hustle-font-family-select.sui-disabled').each(function () {
        self.initiateFontFamilySelects($(this));
        self.toggleCustomFontInput($(this));
      });
    },
    initiateFontFamilySelects: function initiateFontFamilySelects($selects) {
      var force = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

      if ($selects.data('fonts-loaded') === false || force) {
        $selects.SUIselect2('destroy');
        $selects.SUIselect2({
          data: this.fontFamiliesOptions
        });
        $selects.removeClass('sui-disabled');
        $selects.prop('disabled', false);
        $selects.data('fonts-loaded', true);
      }
    },
    fontFamilyUpdated: function fontFamilyUpdated(e) {
      var $select = $(e.currentTarget),
          weightName = $select.data('weight'),
          $weightSelect = this.$("[name=\"".concat(weightName, "\"]")),
          $weightSelectMobile = this.$("[name=\"".concat(weightName, "_mobile\"]")),
          selectedFamily = $select.val(),
          weightSelectOptions = [];
      var availableVariants;

      if (!!selectedFamily) {
        availableVariants = this.fontFamilies[selectedFamily].variants;
      }

      var selected = true;

      if ('undefined' !== typeof availableVariants) {
        var _iterator = _createForOfIteratorHelper(availableVariants),
            _step;

        try {
          for (_iterator.s(); !(_step = _iterator.n()).done;) {
            var variant = _step.value;
            weightSelectOptions.push({
              id: variant,
              text: variant,
              selected: selected
            });

            if (selected === true) {
              selected = false;
            }
          }
        } catch (err) {
          _iterator.e(err);
        } finally {
          _iterator.f();
        }

        $weightSelect.html(weightSelectOptions);
        $weightSelect.SUIselect2('destroy');
        $weightSelect.SUIselect2({
          data: weightSelectOptions
        });
        $weightSelectMobile.html(weightSelectOptions);
        $weightSelectMobile.SUIselect2('destroy');
        $weightSelectMobile.SUIselect2({
          data: weightSelectOptions
        });
      }

      this.toggleCustomFontInput($select);
    },
    applyGlobalFontClicked: function applyGlobalFontClicked(e) {
      var _this3 = this;

      var $applyButton = $(e.currentTarget);
      $applyButton.addClass('sui-button-onload');
      setTimeout(function () {
        _this3.applyGlobalFont();

        $applyButton.removeClass('sui-button-onload');
        Module.Notification.open('success', optinVars.typography.global_font_applied, 4000);
      }, 0);
    },
    applyGlobalFont: function applyGlobalFont() {
      var self = this,
          $selects = this.$('.hustle-font-family-select:not([name="global_font_family"])'),
          globalFont = this.model.get('global_font_family'),
          isCustom = 'custom' === globalFont,
          customGlobalFont = this.model.get('global_custom_font_family');
      var option;
      $selects.each(function () {
        var $select = $(this);

        if ($select.find('option[value="' + globalFont + '"]').length === 0) {
          option = new Option(globalFont, globalFont, true, false);
          $select.empty().val(null).append(option);
        } else {
          $select.val(globalFont);
        }

        $select.trigger('change');

        if (isCustom) {
          var customName = $select.data('custom'),
              $customField = self.$("input[name=\"".concat(customName, "\"]"));
          $customField.val(customGlobalFont).trigger('change');
        }

        self.toggleCustomFontInput($select);
      });
      this.globalFontVariantsUpdated(globalFont);
    },
    globalFontVariantsUpdated: function globalFontVariantsUpdated(fontFamily) {
      var $weightSelect = this.$('.hustle-font-weight'),
          availableVariants = this.fontFamilies[fontFamily].variants,
          weightSelectOptions = [];
      var selected = true;

      if ('undefined' !== typeof availableVariants) {
        var _iterator2 = _createForOfIteratorHelper(availableVariants),
            _step2;

        try {
          for (_iterator2.s(); !(_step2 = _iterator2.n()).done;) {
            var variant = _step2.value;
            weightSelectOptions.push({
              id: variant,
              text: variant,
              selected: selected
            });

            if (selected === true) {
              selected = false;
            }
          }
        } catch (err) {
          _iterator2.e(err);
        } finally {
          _iterator2.f();
        }

        $weightSelect.html(weightSelectOptions);
        $weightSelect.SUIselect2('destroy');
        $weightSelect.SUIselect2({
          data: weightSelectOptions
        });
      }
    },
    toggleCustomFontInput: function toggleCustomFontInput($select) {
      var selectedFamily = $select.val(),
          customName = $select.data('custom'),
          $customFieldWrapper = this.$("input[name=\"".concat(customName, "\"]")).closest('.sui-form-field');

      if ('custom' === selectedFamily) {
        Module.Utils.accessibleShow($customFieldWrapper);
      } else {
        Module.Utils.accessibleHide($customFieldWrapper);
      }
    },
    toggleDeviceTabs: function toggleDeviceTabs() {
      var $deviceTabsMenu = this.$('#hustle-device_settings-tabs > .sui-tabs-menu'),
          $deviceTabsContent = this.$('#hustle-device_settings-tabs > .sui-tabs-content'),
          $deviceTabs = this.$('#hustle-device_settings-tabs'),
          isMobileEnabled = '1' === this.model.get('enable_mobile_settings');

      if (!isMobileEnabled) {
        $deviceTabs.removeClass('hustle-mobile-enabled');
        $deviceTabsMenu.find('#tab-device_settings-desktop').trigger('click');
        $deviceTabsMenu.attr('aria-hidden', true);
        $deviceTabsMenu.attr('hidden', true);
        $deviceTabsContent.find('#tab-content-device_settings-desktop').removeAttr('role');
        $deviceTabsContent.find('#tab-content-device_settings-mobile').attr('aria-hidden', true);
      } else {
        $deviceTabs.addClass('hustle-mobile-enabled');
        $deviceTabsMenu.prop('aria-hidden', false);
        $deviceTabsMenu.prop('hidden', false);
        $deviceTabsContent.find('#tab-content-device_settings-desktop').attr('role', 'tabpanel');
        $deviceTabsContent.find('#tab-content-device_settings-mobile').prop('aria-hidden', false);
      }
    },
    // ============================================================
    // Color Pickers
    initiateColorPickers: function initiateColorPickers(e) {
      var $accordion = $(e.currentTarget);
      var initClass = 'hustle-colorpickers-initialized',
          pickers = $accordion.find('.sui-colorpicker-input');

      if (!$accordion.hasClass(initClass) && pickers.length) {
        $accordion.addClass(initClass);
        this.createPickers(pickers);
      }
    },
    createPickers: function createPickers($suiPickerInputs) {
      var self = this;
      $suiPickerInputs.wpColorPicker({
        change: function change(event, ui) {
          var $this = $(this); // Prevent the model from being marked as changed on load.

          if ($this.val() !== ui.color.toCSS()) {
            $this.val(ui.color.toCSS()).trigger('change');
          }
        },
        palettes: ['#333333', '#FFFFFF', '#17A8E3', '#E1F6FF', '#666666', '#AAAAAA', '#E6E6E6']
      });

      if ($suiPickerInputs.hasClass('wp-color-picker')) {
        $suiPickerInputs.each(function () {
          var $suiPickerType = 'hex';
          var $suiPickerInput = $(this),
              $wpPicker = $suiPickerInput.closest('.wp-picker-container'),
              $wpPickerButton = $wpPicker.find('.wp-color-result'),
              $wpPickerAlpha = $wpPickerButton.find('.color-alpha'),
              $suiPicker = $suiPickerInput.closest('.sui-colorpicker-wrap'),
              $suiPickerColor = $suiPicker.find('.sui-colorpicker-value span[role=button]'),
              $suiPickerValue = $suiPicker.find('.sui-colorpicker-value'),
              $suiPickerClear = $suiPickerValue.find('button'),
              $shownInput = $suiPickerValue.find('.hustle-colorpicker-input'); // Check if alpha exists

          if (true === $suiPickerInput.data('alpha')) {
            $suiPickerType = 'rgba'; // Listen to color change

            $suiPickerInput.on('change', function (e, data) {
              // Change color preview
              $suiPickerColor.find('span').css({
                'background-color': $wpPickerAlpha.css('background')
              }); // We trigger this 'change' manually when the shown input changes.
              // Don't update its value again if this is the case.

              if ('undefined' === typeof data) {
                // Change color value
                $shownInput.val($suiPickerInput.val());
              }
            });
          } else {
            // Listen to color change
            $suiPickerInput.on('change', function (e, data) {
              // Change color preview
              $suiPickerColor.find('span').css({
                'background-color': $wpPickerButton.css('background-color')
              }); // We trigger this 'change' manually when the shown input changes.
              // Don't update its value again if this is the case.

              if ('undefined' === typeof data) {
                // Change color value
                $shownInput.val($suiPickerInput.val());
              }
            });
          } // Allow updating the colors without having to open the colorpicker.


          $shownInput.on('change', function () {
            // Change color value
            $suiPickerInput.val($shownInput.val());
            $suiPickerInput.trigger('change', [{
              triggeredByUs: true
            }]);
          }); // Add picker type class

          $suiPicker.find('.sui-colorpicker').addClass('sui-colorpicker-' + $suiPickerType); // Open iris picker

          $suiPicker.find('.sui-button, span[role=button]').on('click', function (e) {
            $wpPickerButton.click();
            e.preventDefault();
            e.stopPropagation();
          }); // Clear color value

          $suiPickerClear.on('click', function (e) {
            return self.colorPickerCleared(e, $suiPickerInput, self);
          });
        });
      }
    },
    colorPickerCleared: function colorPickerCleared(e, parentSuiPickerInput, parentSelf) {
      var inputName = parentSuiPickerInput.data('attribute'),
          selectedStyle = parentSelf.model.get('color_palette'),
          resetValue = optinVars.palettes[selectedStyle][inputName],
          $suiPicker = parentSuiPickerInput.closest('.sui-colorpicker-wrap'),
          $suiPickerValue = $suiPicker.find('.sui-colorpicker-value'),
          $suiPickerColor = $suiPicker.find('.sui-colorpicker-value span[role=button]'),
          $wpPicker = parentSuiPickerInput.closest('.wp-picker-container'),
          $wpPickerClear = $wpPicker.find('.wp-picker-clear');
      $wpPickerClear.click();
      $suiPickerValue.find('input').val(resetValue);
      parentSuiPickerInput.val(resetValue).trigger('change');
      $suiPickerColor.find('span').css({
        'background-color': resetValue
      });
      e.preventDefault();
      e.stopPropagation();
    },
    updatePickers: function updatePickers(selectedStyle) {
      var self = this;

      if ('undefined' !== typeof optinVars.palettes[selectedStyle]) {
        var colors = optinVars.palettes[selectedStyle]; // update color palettes

        _.each(colors, function (color, key) {
          self.$('input[data-attribute="' + key + '"]').val(color).trigger('change');
        });
      } // TODO: else, display an error message.

    },
    resetSettingsBlock: function resetSettingsBlock(e) {
      var $el = $(e.target);
      $el.addClass('sui-button-onload').prop('disabled', true);

      if ($el.closest('#hustle-color-palette').length) {
        // Reset Pickers
        var style = $('select[data-attribute="color_palette"]').val();
        this.updatePickers(style);
      } else {
        // Reset other block types
        var parent = $el.closest('.sui-accordion');
        var ev = jQuery.Event("click");
        ev.currentTarget = parent;
        this.initiateFontFamilySelectOnAccordionClick(ev);
        var settings = parent.find('[data-attribute]');
        settings.each(function () {
          var $field = $(this);
          var fieldName = $field.attr('name');

          if ('undefined' !== typeof optinVars.defaults[fieldName]) {
            var value = optinVars.defaults[fieldName],
                suiTabs = $field.parent('.sui-tabs');
            $field.val(value);

            if ('radio' !== $field.prop('type') || !$field.parent('.sui-tabs')) {
              // other cases
              $field.trigger('sui:change').trigger('change');
            } else {
              // changing SUI tabs
              $('#tab-' + fieldName + '-' + value, suiTabs).trigger('click');
            }
          }
        });
      }

      setTimeout(function () {
        $el.removeClass('sui-button-onload').prop('disabled', false);
      }, 500);
    },

    /**
     * Add the "Create custom palette button" to the existing palettes dropdown.
     * The select's options are re-rendered every time they're opened.
     *
     * @since 4.0.3
     */
    addCreatePalettesLink: function addCreatePalettesLink() {
      var _this4 = this;

      // Delay appending this so it's not overriden by select2's options.
      setTimeout(function () {
        var $link = _this4.$('#hustle-create-palette-link li'),
            $selectPaletteContainer = $('#select2-hustle-color-palettes-list-results'),
            $selectButton = $selectPaletteContainer.find('.hui-button');

        if (!$selectButton.length) {
          $link.clone().appendTo($selectPaletteContainer);
        }
      }, 500);
    },
    // ============================================================
    // CSS Editor
    createEditor: function createEditor(id) {
      var cssEditor = ace.edit(id);
      cssEditor.getSession().setMode('ace/mode/css');
      cssEditor.$blockScrolling = Infinity;
      cssEditor.setTheme('ace/theme/sui');
      cssEditor.getSession().setUseWrapMode(true);
      cssEditor.getSession().setUseWorker(false);
      cssEditor.setShowPrintMargin(false);
      cssEditor.renderer.setShowGutter(true);
      cssEditor.setHighlightActiveLine(true);
      return cssEditor;
    },
    updateCustomCss: function updateCustomCss() {
      if (this.cssEditor) {
        this.model.set('custom_css', this.cssEditor.getValue());
      }
    },
    insertSelector: function insertSelector(e) {
      var $el = $(e.target),
          stylable = $el.data('stylable') + '{}',
          cssEditor = this.cssEditor;
      cssEditor.navigateFileEnd();
      cssEditor.insert(stylable);
      cssEditor.navigateLeft(1);
      cssEditor.focus();
      e.preventDefault();
    },
    // ============================================================
    // Adjust the view when the Design model is updated.
    modelUpdated: function modelUpdated() {
      this.addUpdatedProperty();
      this.updateViewOnModelUpdate();
    },
    addUpdatedProperty: function addUpdatedProperty() {
      _.extend(this.updatedProperties, this.model.changed);
    },
    updateViewOnModelUpdate: function updateViewOnModelUpdate() {
      var model = this.model,
          //changed = model.changed,
      changedkey = Object.keys(model.changed)[0],
          actionToDo = this.getActionOnModelUpdated(changedkey);

      if ('undefined' !== typeof actionToDo) {
        actionToDo(changedkey);
      }
    },
    getActionOnModelUpdated: function getActionOnModelUpdated(changedKey) {
      var _this5 = this;

      var functions = {
        color_palette: function color_palette() {
          return _this5.updatePickers(_this5.model.changed.color_palette);
        },
        cta_buttons_alignment: function cta_buttons_alignment() {
          return _this5.toggleCtaButtonsTextAlignment();
        },
        cta_buttons_alignment_mobile: function cta_buttons_alignment_mobile() {
          return _this5.toggleCtaButtonsTextAlignment();
        },
        enable_mobile_settings: function enable_mobile_settings() {
          return _this5.toggleDeviceTabs();
        },
        feature_image_hide_on_mobile: function feature_image_hide_on_mobile(prop) {
          return _this5.hideOtherOptionsInAcordionItem(prop, '1' === _this5.model.get(prop));
        },
        feature_image_fit: function feature_image_fit(prop) {
          return _this5.toggleFeatureImageSizeSettingRow(prop);
        },
        // Hide other Options for Mobile Feature Image.
        feature_image_fit_mobile: function feature_image_fit_mobile(prop) {
          return _this5.toggleFeatureImageSizeSettingRow(prop);
        },
        feature_image_position: function feature_image_position() {
          return _this5.toggleFeatureImageSizeRows();
        },
        form_layout: function form_layout() {
          _this5.setImageAligmentOptions();

          _this5.toggleFeatureImageSizeRows();
        },
        style: function style() {
          return _this5.handleStyleChange();
        },
        use_vanilla: function use_vanilla() {
          return _this5.setVanillaThemeVisibility();
        }
      };
      return functions[changedKey];
    },
    toggleCtaButtonsTextAlignment: function toggleCtaButtonsTextAlignment() {
      var $ctaTypographyAccordionDesktop = this.$('#hustle-cta_alignment-form-field'),
          $ctaTypographyAccordionMobile = this.$('#hustle-cta_alignment_mobile-form-field');

      if ('full' === this.model.get('cta_buttons_alignment')) {
        Module.Utils.accessibleShow($ctaTypographyAccordionDesktop);
      } else {
        Module.Utils.accessibleHide($ctaTypographyAccordionDesktop);
      }

      if ('full' === this.model.get('cta_buttons_alignment_mobile')) {
        Module.Utils.accessibleShow($ctaTypographyAccordionMobile);
      } else {
        Module.Utils.accessibleHide($ctaTypographyAccordionMobile);
      }
    },
    hideOtherOptionsInAcordionItem: function hideOtherOptionsInAcordionItem(inputName, hide) {
      var $this = this.$('[name="' + inputName + '"]'),
          $parent = $this.closest('.sui-box'),
          $parentRow = $parent.find('.sui-box-settings-row').slice(0, 1),
          $nextRows = $parent.find('.sui-box-settings-row').slice(1);

      if (!hide) {
        $nextRows.removeClass('sui-hidden-important');
        $parentRow.removeClass('hustle-no-bottom-line');
      } else {
        $nextRows.addClass('sui-hidden-important');
        $parentRow.addClass('hustle-no-bottom-line');
      }
    },
    toggleFeatureImageSizeSettingRow: function toggleFeatureImageSizeSettingRow() {
      var changedKey = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : false;

      if (!changedKey || 'feature_image_fit' === changedKey) {
        var $sizeRow = this.$('#hustle-feature-image-size-settings-row'),
            value = this.model.get('feature_image_fit');

        if ('none' !== value) {
          $sizeRow.show();
        } else {
          $sizeRow.hide();
        }
      }

      if (!changedKey || 'feature_image_fit_mobile' === changedKey) {
        var _$sizeRow = this.$('#hustle-feature-image-size-mobile-settings-row'),
            _value = this.model.get('feature_image_fit_mobile');

        if ('none' !== _value) {
          _$sizeRow.show();
        } else {
          _$sizeRow.hide();
        }
      }
    },
    handleStyleChange: function handleStyleChange() {
      var style = this.model.get('style'),
          $layoutMain = this.$('[data-name="module_cont"]'),
          $layoutHeader = this.$('[data-name="layout_header"]'),
          $layoutContent = this.$('[data-name="layout_content"]'),
          $layoutFooter = this.$('[data-name="layout_footer"]'); // Replace "Main Layout" classname on note field.

      if ('cabriolet' === style) {
        $layoutMain.find('.sui-accordion-item-title .sui-accordion-note').text('.hustle-layout-body');
      } else {
        $layoutMain.find('.sui-accordion-item-title .sui-accordion-note').text('.hustle-layout');
      } // Hide "Layout Content" and show "Layout Footer" row for Default (minimal) style.


      if ('minimal' !== style) {
        Module.Utils.accessibleHide($layoutContent);
        Module.Utils.accessibleHide($layoutFooter);
      } else {
        Module.Utils.accessibleShow($layoutContent);
        Module.Utils.accessibleShow($layoutFooter);
      } // Hide the "Layout Header" row for Compact (simple) layout.


      if ('simple' !== style) {
        Module.Utils.accessibleShow($layoutHeader);
      } else {
        Module.Utils.accessibleHide($layoutHeader);
      }
    },
    setVanillaThemeVisibility: function setVanillaThemeVisibility() {
      var vanillaElements = this.$('[data-toggle-content="use-vanilla"]'),
          $nonVanillaElements = this.$('[data-toggle-content="not-use-vanilla"]');

      if (this.model.get('use_vanilla') === '0') {
        Module.Utils.accessibleShow(vanillaElements, true);
        Module.Utils.accessibleHide($nonVanillaElements, true);
      } else {
        Module.Utils.accessibleHide(vanillaElements, true);
        Module.Utils.accessibleShow($nonVanillaElements, true);
      }
    },
    // Update linked fields values when re-linked.
    linkFieldsChanged: function linkFieldsChanged(e) {
      var $input = $(e.currentTarget); // Fields were unlinked. No need to do anything.

      if ('0' === $input.val()) {
        return;
      } // Fields were linked. Update their values using the first field's value.


      var linkName = $input.attr('name'),
          $linkedFields = this.$("[data-linked-fields=".concat(linkName, "]")),
          firstFieldVal = $linkedFields[0].value;
      $linkedFields.val(firstFieldVal).trigger('change', {
        updatedByUs: true
      });
    },
    // Keep linked fields linked on change.
    linkedFieldsChanged: function linkedFieldsChanged(e, data) {
      // The fields were updated manually by us. Bail out and don't trigger that infinite loop.
      if (data) {
        return;
      }

      var $input = $(e.currentTarget),
          linkName = $input.data('linked-fields'); // The fields are unlinked. Nothing to do here.

      if ('1' !== this.model.get(linkName)) {
        return;
      }

      var $linkedFields = this.$("[data-linked-fields=".concat(linkName, "]"));
      $linkedFields.val($input.val()).trigger('change', {
        updatedByUs: true
      });
    },
    requiredFieldChanged: function requiredFieldChanged(e) {
      var $field = $(e.currentTarget),
          isEmpty = 0 === $field.val().trim().length;

      if (isEmpty) {
        var fieldName = $field.attr('name');

        if ('undefined' !== typeof optinVars.defaults[fieldName]) {
          $field.val(optinVars.defaults[fieldName]);
        }
      }
    },
    // Show or hide the positions available for each form layout.
    setImageAligmentOptions: function setImageAligmentOptions() {
      var $targetAbove = this.$('#tab-feature_image_position-alignment-above'),
          $targetBelow = this.$('#tab-feature_image_position-alignment-below');

      if ('one' === this.model.get('form_layout')) {
        Module.Utils.accessibleShow($targetAbove, true);
        Module.Utils.accessibleShow($targetBelow, true);
      } else {
        var imgPosition = this.model.get('feature_image_position');

        if ('left' !== imgPosition && 'right' !== imgPosition) {
          this.$('#tab-feature_image_position-alignment-left').trigger('click'); // The model's isn't triggering a change of feature_image_position for some reason.
          // TODO: Find and fix that. Then remove this function call.

          this.toggleFeatureImageSizeRows();
        }

        Module.Utils.accessibleHide($targetAbove, true);
        Module.Utils.accessibleHide($targetBelow, true);
      }
    },
    toggleFeatureImageSizeRows: function toggleFeatureImageSizeRows() {
      var $widthRow = this.$('#hustle-feature_image_width-row'),
          $widthDescription = this.$('#hustle-feature-image-desktop-width-description'),
          $heightRow = this.$('#hustle-feature_image_height-row'),
          $heightDescription = this.$('#hustle-feature-image-desktop-height-description'),
          contentDependentProps = ['title', 'sub_title', 'show_cta', 'main_content'],
          formLayout = this.model.get('form_layout');

      var showHeight = function showHeight() {
        $heightRow.show();
        $heightDescription.show();
        $widthRow.hide();
        $widthDescription.hide();
      },
          showWidth = function showWidth() {
        $heightRow.hide();
        $heightDescription.hide();
        $widthRow.show();
        $widthDescription.show();
      },
          showBoth = function showBoth() {
        $heightRow.show();
        $heightDescription.hide();
        $widthRow.show();
        $widthDescription.show();
      }; // Use only the height field when there's no title, subtitle, cta, nor main content.


      var isFeatureImageOnly = true;

      for (var _i = 0, _contentDependentProp = contentDependentProps; _i < _contentDependentProp.length; _i++) {
        var prop = _contentDependentProp[_i];

        if (this.contentPropIsShown[prop]) {
          isFeatureImageOnly = false;
        }
      }

      if (isFeatureImageOnly && 'two' !== formLayout && 'four' !== formLayout) {
        showHeight();
        return;
      } // Informational modules never use the height other than in the case above.


      if (!optinVars.current.is_optin) {
        showWidth();
        return;
      }

      if ('three' === formLayout) {
        showHeight();
        return;
      }

      if ('four' === formLayout) {
        if (isFeatureImageOnly) {
          showWidth();
        } else {
          showBoth();
        }

        return;
      }

      var imageAlignment = this.model.get('feature_image_position');

      if ('below' === imageAlignment || 'above' === imageAlignment) {
        showHeight();
      } else {
        showWidth();
      }
    },
    updateFeatureImageWidth: function updateFeatureImageWidth(e) {
      var $predefinedSelect = $(e.currentTarget),
          predefinedValue = $predefinedSelect.val(),
          $widthValueInput = this.$('input[name="feature_image_width"]'); // TODO: implement the global handler for disable/enable.

      if ('custom' !== predefinedValue) {
        var $widthUnitSelect = this.$('select[name="feature_image_width_unit"]');
        $widthUnitSelect.val('%').trigger('sui:change').trigger('change');
        $widthValueInput.prop('disabled', true);
        $widthValueInput.val(predefinedValue).trigger('change');
      } else {
        $widthValueInput.prop('disabled', false);
      }
    },
    // ============================================================
    // Adjust the view according to the Content model.
    contentModelUpdated: function contentModelUpdated(changed) {
      var changedKey = Object.keys(changed)[0],
          actionToDo = this.getActionOnContentModelUpdated(changedKey);

      if ('undefined' !== typeof actionToDo) {
        actionToDo(changed, changedKey);
        this.toggleFeatureImageSizeRows();
        this.updateElementsRow(changedKey);
      }
    },
    setVisibilityOnRender: function setVisibilityOnRender() {
      this.contentPropIsShown.feature_image = '' !== optinVars.current.content.feature_image;
      this.contentPropIsShown.background_image = '' !== optinVars.current.content.background_image;
      this.contentPropIsShown.show_cta = '0' !== optinVars.current.content.show_cta;
      this.contentPropIsShown.title = '' !== optinVars.current.content.title;
      this.contentPropIsShown.sub_title = '' !== optinVars.current.content.sub_title;
      this.contentPropIsShown.show_never_see_link = '0' !== optinVars.current.content.show_never_see_link;
      this.contentPropIsShown.optin_form = optinVars.current.is_optin;
      this.contentPropIsShown.main_content = '' !== optinVars.current.content.main_content;
    },
    getActionOnContentModelUpdated: function getActionOnContentModelUpdated(changedKey) {
      var _this6 = this;

      var functions = {
        // Uploading a featured image makes the "Featured Image settings" show up in the "Appearance" tab.
        background_image: function background_image(changed) {
          return _this6.contentPropIsShown.background_image = '' !== changed.background_image;
        },
        // Update this view when "Feature image" is changed in the Content tab.
        feature_image: function feature_image(changed) {
          _this6.contentPropIsShown.feature_image = '' !== changed.feature_image;

          _this6.hideOtherOptionsInAcordionItem('feature_image_position', !_this6.contentPropIsShown.feature_image);
        },
        main_content: function main_content(changed) {
          return _this6.contentPropIsShown.main_content = '' !== changed.main_content;
        },
        show_cta: function show_cta(changed) {
          return _this6.contentPropIsShown.show_cta = '0' !== changed.show_cta;
        },
        show_never_see_link: function show_never_see_link(changed) {
          return _this6.contentPropIsShown.show_never_see_link = '0' !== changed.show_never_see_link;
        },
        sub_title: function sub_title(changed) {
          return _this6.contentPropIsShown.sub_title = '' !== changed.sub_title;
        },
        title: function title(changed) {
          return _this6.contentPropIsShown.title = '' !== changed.title;
        }
      };
      return functions[changedKey];
    },
    updateElementsRow: function updateElementsRow(changedKey) {
      var $row = this.$('#hustle-wizard-appearance-desktop, #hustle-wizard-appearance-mobiles');
      var $accordion = $row.find(".sui-accordion-item[data-name=\"".concat(changedKey, "\"]")),
          doShow = this.contentPropIsShown[changedKey];

      if (doShow) {
        $accordion.show();
      } else {
        $accordion.hide();
      } // The Advanced and Typography rows (the ones checked in the function)
      // always remain displayed for optin modules.


      if (!optinVars.current.is_optin) {
        this.updateRow(changedKey);
      } else {
        this.handleTypographyTabs(changedKey);
      }
    },
    updateRow: function updateRow(changedKey) {
      var rows = {
        'hustle-typography-elements-row': ['show_cta', 'title', 'sub_title', 'main_content'],
        'hustle-appearance-customize-elements-row': ['feature_image', 'background_image', 'show_cta']
      };
      var self = this;
      $.each(rows, function (rowClass, dependentProps) {
        if (dependentProps.includes(changedKey)) {
          var doShowRow = false;

          var _iterator3 = _createForOfIteratorHelper(dependentProps),
              _step3;

          try {
            for (_iterator3.s(); !(_step3 = _iterator3.n()).done;) {
              var prop = _step3.value;

              if (self.contentPropIsShown[prop]) {
                doShowRow = true;
              }
            }
          } catch (err) {
            _iterator3.e(err);
          } finally {
            _iterator3.f();
          }

          if (doShowRow) {
            $('.' + rowClass).show();
          } else {
            $('.' + rowClass).hide();
          }
        }
      });
    },
    handleTypographyTabs: function handleTypographyTabs(changedKey) {
      var dependentProps = ['show_cta', 'title', 'sub_title', 'main_content'];

      if ('embedded' !== optinVars.current.data.module_type) {
        dependentProps.push('show_never_see_link');
      }

      if (dependentProps.includes(changedKey)) {
        var $tabs = this.$('.hustle-typography-tabs'),
            $tabsMenu = $tabs.find('.sui-tabs-menu');
        var doShowGeneralTab = false;

        var _iterator4 = _createForOfIteratorHelper(dependentProps),
            _step4;

        try {
          for (_iterator4.s(); !(_step4 = _iterator4.n()).done;) {
            var prop = _step4.value;

            if (this.contentPropIsShown[prop]) {
              doShowGeneralTab = true;
            }
          }
        } catch (err) {
          _iterator4.e(err);
        } finally {
          _iterator4.f();
        }

        if (doShowGeneralTab) {
          Module.Utils.accessibleShow($tabsMenu);
        } else {
          Module.Utils.accessibleHide($tabsMenu);
          $tabs.find('#tab-custom-typography-optin').trigger('click');
          $tabs.find('#tab-custom-typography_mobile-optin').trigger('click');
        }
      }
    },
    // ============================================================
    // Adjust the view according to the Emails model.
    emailsModelUpdated: function emailsModelUpdated(changed) {
      var changedKey = Object.keys(changed)[0],
          actionToDo = this.getActionOnEmailsModelUpdated(changedKey);

      if ('undefined' !== typeof actionToDo) {
        actionToDo(changed, changedKey); //this.updateElementsRow( changedKey );
      }
    },
    getActionOnEmailsModelUpdated: function getActionOnEmailsModelUpdated(changedKey) {
      var _this7 = this;

      var functions = {
        form_elements: function form_elements(changed) {
          return _this7.formFieldsUpdated(changed);
        },
        after_successful_submission: function after_successful_submission(changed) {
          return _this7.setSucccessfulMessageOptionVisibility(changed);
        }
      };
      return functions[changedKey];
    },
    // TODO: Fix not working for colors.
    setSucccessfulMessageOptionVisibility: function setSucccessfulMessageOptionVisibility(model) {
      var $divSettings = this.$('[data-name="success_message"]');

      if ($divSettings.length > 0) {
        if ('show_success' === model.after_successful_submission) {
          $divSettings.show();
        } else {
          $divSettings.hide();
        }
      }
    },
    formFieldsUpdated: function formFieldsUpdated(model) {
      this.handleRecaptcha(model.form_elements);
      this.handleGdpr(model.form_elements);
      this.handleCalendar(model.form_elements);
    },

    /**
     * Triggered when 'form_elements' in the emails model is updated.
     *
     * @since 4.3.0
     *
     * @param {Object} formFields Current form field elements.
     */
    handleRecaptcha: function handleRecaptcha(formFields) {
      var $recaptchaSettings = this.$('[data-name="recaptcha"]');
      var recaptcha = false;

      if ('undefined' !== typeof formFields.recaptcha) {
        recaptcha = 'v3_recaptcha' === formFields.recaptcha.version && '0' === formFields.recaptcha.v3_recaptcha_show_badge || 'v2_invisible' === formFields.recaptcha.version && '0' === formFields.recaptcha.v2_invisible_show_badge;
      }

      if (recaptcha) {
        $recaptchaSettings.show();
      } else {
        $recaptchaSettings.hide();
      }
    },
    handleGdpr: function handleGdpr(formFields) {
      var $gdprSettings = this.$('[data-name="gdpr"]');

      if ('undefined' !== typeof formFields.gdpr) {
        $gdprSettings.show();
      } else {
        $gdprSettings.hide();
      }
    },
    handleCalendar: function handleCalendar(formFields) {
      var hasCalendar = false;

      for (var fieldSlug in formFields) {
        var field = formFields[fieldSlug];

        if ('calendar' === field.type) {
          hasCalendar = true;
          break;
        }
      }

      if (hasCalendar) {
        this.$('[data-name="calendar"]').show();
      } else {
        this.$('[data-name="calendar"]').hide();
      }
    },
    // ============================================================
    // Adjust the view according to the Integrations model.
    integrationsModelUpdate: function integrationsModelUpdate(model) {
      if ('active_integrations' in model.changed) {
        this.updateMailchimpRelatedAccordions(model.changed);
      }
    },
    updateMailchimpRelatedAccordions: function updateMailchimpRelatedAccordions(model) {
      var activeIntegrations = model.active_integrations.split(','),
          hasMailchimp = activeIntegrations.includes('mailchimp'),
          dependentProps = ['form_extras', 'checkbox', 'dropdown', 'select'];

      for (var _i2 = 0, _dependentProps = dependentProps; _i2 < _dependentProps.length; _i2++) {
        var prop = _dependentProps[_i2];

        if (hasMailchimp) {
          this.$("[data-name=\"".concat(prop, "\"]")).show();
        } else {
          this.$("[data-name=\"".concat(prop, "\"]")).hide();
        }
      }
    }
  });
});
Hustle.define('Mixins.Module_Display', function () {
  'use strict';

  return _.extend({}, Hustle.get('Mixins.Model_Updater'), {
    el: '#hustle-wizard-display',
    events: {},
    init: function init(opts) {
      this.model = new opts.BaseModel(optinVars.current.display || {});
      this.moduleType = optinVars.current.data.module_type;
      this.listenTo(this.model, 'change', this.viewChanged); // Called just to trigger the "view.rendered" action.

      this.render();
    },
    render: function render() {},
    viewChanged: function viewChanged() {}
  });
});
function _createForOfIteratorHelper(o, allowArrayLike) { var it; if (typeof Symbol === "undefined" || o[Symbol.iterator] == null) { if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || allowArrayLike && o && typeof o.length === "number") { if (it) o = it; var i = 0; var F = function F() {}; return { s: F, n: function n() { if (i >= o.length) return { done: true }; return { done: false, value: o[i++] }; }, e: function e(_e) { throw _e; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var normalCompletion = true, didErr = false, err; return { s: function s() { it = o[Symbol.iterator](); }, n: function n() { var step = it.next(); normalCompletion = step.done; return step; }, e: function e(_e2) { didErr = true; err = _e2; }, f: function f() { try { if (!normalCompletion && it.return != null) it.return(); } finally { if (didErr) throw err; } } }; }

function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }

function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) { arr2[i] = arr[i]; } return arr2; }

Hustle.define('Mixins.Module_Emails', function ($) {
  'use strict';

  return _.extend({}, Hustle.get('Mixins.Model_Updater'), {
    el: '#hustle-wizard-emails',
    events: {
      'click .hustle-optin-field--add': 'addFields',
      'click .hustle-optin-field--edit': 'editField',
      'click .sui-builder-field': 'maybeEditField',
      'click .hustle-optin-field--delete': 'deleteFieldOnClick',
      'click ul.list-results li': 'setFieldOption',
      'click .hustle-optin-field--copy': 'duplicateField'
    },
    init: function init(opts) {
      this.model = new opts.BaseModel(optinVars.current.emails || {});
      this.listenTo(this.model, 'change', this.modelUpdated);
      this.render();
    },
    render: function render() {
      var self = this,
          formElements = this.model.get('form_elements'); // Add the already stored form fields to the panel.

      for (var fieldId in formElements) {
        var field = formElements[fieldId]; // Assign the defaults for the field, in case there's anything missing.

        formElements[fieldId] = _.extend({}, this.getFieldDefaults(field.type), field); // Submit is already at the bottom of the panel. We don't want to add it again.

        if ('submit' === fieldId) {
          continue;
        }

        self.addFieldToPanel(formElements[fieldId]);
      } // update form_elements for having default properties if they were lost for some reason


      this.model.set('form_elements', formElements, {
        silent: true
      }); // Initiate the sortable functionality to sort form fields' order.

      var sortableContainer = this.$('#hustle-form-fields-container').sortable({
        axis: 'y',
        containment: '.sui-box-builder'
      });
      sortableContainer.on('sortupdate', $.proxy(self.fieldsOrderChanged, self, sortableContainer));
      this.$('#hustle-email-day').datepicker({
        beforeShow: function beforeShow() {
          $('#ui-datepicker-div').addClass('sui-calendar');
        },
        dateFormat: 'MM dd, yy'
      });
      this.$('#hustle-email-time').timepicker({
        timeFormat: 'h:mm p',
        interval: '1',
        minTime: '0',
        maxTime: '11:59pm',
        defaultTime: null,
        startTime: '00:00',
        dynamic: false,
        dropdown: true,
        scrollbar: true,
        change: function change() {
          $('#hustle-email-time').trigger('change');
        }
      });
      this.updateDynamicValueFields();
      return this;
    },

    /**
     * Handle the changes in the view when the model is updated.
     *
     * @since 4.3.0
     *
     * @param {Object} model The model for this view.
     */
    modelUpdated: function modelUpdated(model) {
      var changed = model.changed,
          changedKey = Object.keys(changed)[0],
          actionToDo = this.getActionOnModelUpdated(changedKey);

      if ('undefined' !== typeof actionToDo) {
        actionToDo(changed);
      }

      Hustle.Events.trigger('modules.view.emailsUpdate', changed);
    },

    /**
     * Launches events when some actions are made.
     *
     * @since 4.3.0
     *
     * @param {string} changedKey Action name.
     */
    getActionOnModelUpdated: function getActionOnModelUpdated(changedKey) {
      var _this = this;

      var functions = {
        auto_close_success_message: function auto_close_success_message() {
          return _this.autoCloseSuccessMessageUpdated();
        },
        form_elements: function form_elements() {
          return _this.updateDynamicValueFields();
        }
      };
      return functions[changedKey];
    },
    autoCloseSuccessMessageUpdated: function autoCloseSuccessMessageUpdated() {
      var $targetDiv = this.$('#section-auto-close-success-message .sui-row');

      if ('1' === this.model.get('auto_close_success_message')) {
        $targetDiv.removeClass('sui-hidden');
      } else {
        $targetDiv.addClass('sui-hidden');
      }
    },
    //reset all field selects
    resetDynamicValueFieldsPlaceholders: function resetDynamicValueFieldsPlaceholders() {
      this.$('select.hustle-field-options').html('');

      if (this.$('.hustle-fields-placeholders-options').length) {
        this.$('.hustle-fields-placeholders-options').html('');
      }
    },
    //update all field selects
    updateDynamicValueFields: function updateDynamicValueFields() {
      var formElements = this.model.get('form_elements');
      this.resetDynamicValueFieldsPlaceholders();

      for (var fieldId in formElements) {
        if ('submit' === fieldId || 'recaptcha' === fieldId || 'gdpr' === fieldId) {
          continue;
        }

        this.addFieldToDynamicValueFields(formElements[fieldId]);
        this.$('select.hustle-field-options').trigger('sui:change');
      } //set info notice for empty dynamic fields select


      this.$('div.select-list-container .list-results:empty').each(function () {
        var fieldType = $(this).closest('.select-container').find('select.hustle-field-options').data('type');
        $(this).html('<li style="cursor: default; pointer-events: none;">' + optinVars.form_fields.no_fields_of_type_notice.replace('{field_type}', fieldType) + '</li>');
      });
    },

    /**
     * Assign the new field order to the model. Triggered when the fields are sorted.
     *
     * @since 4.0.0
     * @param {Object} sortable jQuery sortable object.
     */
    fieldsOrderChanged: function fieldsOrderChanged(sortable) {
      var formElements = this.model.get('form_elements'),
          newOrder = sortable.sortable('toArray', {
        attribute: 'data-field-id'
      });
      var orderedFields = {};

      var _iterator = _createForOfIteratorHelper(newOrder),
          _step;

      try {
        for (_iterator.s(); !(_step = _iterator.n()).done;) {
          var id = _step.value;
          orderedFields[id] = formElements[id];
        }
      } catch (err) {
        _iterator.e(err);
      } finally {
        _iterator.f();
      }

      orderedFields = _.extend({}, orderedFields, formElements);
      this.model.set('form_elements', orderedFields);
    },

    /**
     * Open the "Add new fields" modal.
     *
     * @since 4.0
     * @param {Event} e Event.
     */
    addFields: function addFields(e) {
      // Show dialog
      SUI.openModal('hustle-dialog--optin-fields', $(e.currentTarget)[0], this.$('#hustle-dialog--optin-fields .sui-box-header .sui-button-icon')[0], true);
      var OptinFieldsModalView = Hustle.get('Modals.Optin_Fields'),
          newFieldModal = new OptinFieldsModalView({
        model: this.model
      }); // Create the fields and append them to panel.

      newFieldModal.on('fields:added', $.proxy(this.addNewFields, this));
    },
    maybeEditField: function maybeEditField(e) {
      var $ct = $(e.target);

      if (!$ct.closest('.sui-dropdown').length) {
        this.editField(e);
      }
    },

    /**
     * Open the "edit field" modal.
     *
     * @since 4.0.0
     * @param {event} e Event.
     */
    editField: function editField(e) {
      var $button = $(e.target),
          fieldId = $button.closest('.sui-builder-field').data('field-id'),
          existingFields = this.model.get('form_elements'),
          field = existingFields[fieldId],
          fieldData = Object.assign({}, this.getFieldViewDefaults(field.type), field),
          EditFieldModalView = Hustle.get('Modals.Edit_Field'),
          editModalView = new EditFieldModalView({
        field: field,
        fieldData: fieldData,
        model: this.model
      });
      editModalView.on('field:updated', $.proxy(this.formFieldUpdated, this)); // Show dialog.

      SUI.openModal('hustle-dialog--edit-field', $button[0], this.$('#hustle-dialog--edit-field .sui-box-header .sui-button-icon')[0], true);
    },

    /**
     * Update the appearance of the form field row of the field that was updated.
     *
     * @since 4.0.0
     *
     * @param {Object} updatedField Field properties after the update.
     * @param {Object} changed Field properties that were updated.
     * @param {Object} oldField Field properties before the update.
     */
    formFieldUpdated: function formFieldUpdated(updatedField, changed, oldField) {
      if (!Object.keys(changed).length) {
        return;
      } // Name is the unique identifier.
      // If it changed, update the existing fields removing the old one and creating a new one.


      if ('name' in changed) {
        this.addNewFields(updatedField.type, updatedField, oldField.name);
        this.deleteField(oldField.name);
        return;
      }

      var $fieldRow = this.$('#hustle-optin-field--' + updatedField.name);

      if ('required' in changed) {
        var $requiredTag = $fieldRow.find('.sui-error'),
            isRequired = updatedField.required; // Show the "required" asterisk to this field's row.

        if (_.isTrue(isRequired)) {
          $requiredTag.show();
        } else if (_.isFalse(isRequired)) {
          // Hide the "required" asterisk to this field's row.
          $requiredTag.hide();
        }
      }

      if ('label' in changed) {
        this.updateDynamicValueFields();
        var $labelWrapper = $fieldRow.find('.hustle-field-label-text');
        $labelWrapper.text(updatedField.label);
      }
    },
    deleteFieldOnClick: function deleteFieldOnClick(e) {
      var $button = $(e.target),
          fieldName = $button.closest('.sui-builder-field').data('field-id');
      this.deleteField(fieldName);
    },
    setFieldOption: function setFieldOption(e) {
      var $li = $(e.target),
          val = $li.find('span:eq(1)').text(),
          $input = $li.closest('.sui-insert-variables').find('input[type="text"]');
      $input.val(val).trigger('change');
    },
    deleteField: function deleteField(fieldName) {
      var $fieldRow = this.$('#hustle-optin-field--' + fieldName),
          formElements = Object.assign({}, this.model.get('form_elements'));
      delete formElements[fieldName];
      this.model.set('form_elements', formElements);

      if (-1 !== jQuery.inArray(fieldName, ['gdpr', 'recaptcha'])) {
        $fieldRow.addClass('sui-hidden');
        $('#hustle-optin-insert-field--' + fieldName).prop('disabled', false).prop('checked', false);
      } else {
        $fieldRow.remove();
      }
    },
    duplicateField: function duplicateField(e) {
      var $button = $(e.target),
          fieldId = $button.closest('.sui-builder-field').data('field-id'),
          formElements = Object.assign({}, this.model.get('form_elements')),
          duplicatedField = Object.assign({}, formElements[fieldId]); // Remove 'name' because it should be an unique identifier. Will be added in 'add_new_fields'.

      delete duplicatedField.name; // Make the field deletable because it can't be deleted otherwise, and you'll have it stuck forevah.

      duplicatedField.can_delete = true; // eslint-disable-line camelcase

      this.addNewFields(duplicatedField.type, duplicatedField);
    },

    /**
     * Used to add new fields.
     *	When using form_fields, make sure only 1 type of each field is added.
     *	In other words, use field.type as an unique identifier.
     *
     * @since 4.0.0
     *
     * @param {Array|string} formFields Field or set of fields to add.
     * @param {Object} formFieldsData Field data to include in the new field.
     * @param {string|null} oldFieldName Field name before the update.
     */
    addNewFields: function addNewFields(formFields, formFieldsData) {
      var oldFieldName = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : null;
      var self = this;
      var existingFields = Object.assign({}, this.model.get('form_elements'));

      if (Array.isArray(formFields)) {
        var _iterator2 = _createForOfIteratorHelper(formFields),
            _step2;

        try {
          for (_iterator2.s(); !(_step2 = _iterator2.n()).done;) {
            var field = _step2.value;
            var fieldData = self.getFieldDefaults(field);

            if (formFieldsData && field in formFieldsData) {
              _.extend(fieldData, formFieldsData[field]);
            }

            self.addFieldToPanel(fieldData);
            existingFields[fieldData.name] = fieldData;
          }
        } catch (err) {
          _iterator2.e(err);
        } finally {
          _iterator2.f();
        }
      } else {
        var _fieldData = self.getFieldDefaults(formFields);

        if (formFieldsData) {
          _.extend(_fieldData, formFieldsData);
        }

        self.addFieldToPanel(_fieldData, oldFieldName);

        if (null === oldFieldName) {
          existingFields[_fieldData.name] = _fieldData;
        } else {
          var reorderExistingFields = [];
          jQuery.each(existingFields, function (index, data) {
            reorderExistingFields[index] = data;

            if (index === oldFieldName) {
              reorderExistingFields[_fieldData.name] = _fieldData;
            }
          });
          existingFields = reorderExistingFields;
        }
      }

      this.model.set('form_elements', existingFields);
    },

    /**
     * Add a field to the fields with dynamic values for the automated emails.
     * The field object must have all its core prop assigned. The views prop are assigned here.
     *
     * @since 4.0
     * @param {Object} field Properties of the field.
     */
    addFieldToDynamicValueFields: function addFieldToDynamicValueFields(field) {
      // escape name and label.
      var temp;
      temp = $('<div>' + field.name + '</div>');
      temp.find('script').remove();
      field.name = temp.html();
      temp = $('<div>' + field.label + '</div>');
      temp.find('script').remove();
      field.label = temp.html();
      var option = $('<option/>', {
        value: field.name,
        'data-content': '{' + field.name + '}'
      }).text(field.label),
          listOption = "<li><button value=\"{".concat(field.name, "}\">").concat(field.label, "</button></li>");
      this.$('select.hustle-field-options:not([data-type]), select.hustle-field-options[data-type="' + field.type + '"]').append(option);

      if (this.$('.hustle-fields-placeholders-options').length) {
        this.$('.hustle-fields-placeholders-options').append(listOption);
      }
    },

    /**
     * Add a field to the fields pannel.
     * The field object must have all its core prop assigned. The views prop are assigned here.
     *
     * @since 4.0.0
     *
     * @param {Object} field Field properties to add.
     * @param {string|null} oldFieldName Old field name if we're updating a field's name.
     */
    addFieldToPanel: function addFieldToPanel(field) {
      var oldFieldName = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;
      var template = Optin.template('hustle-form-field-row-tpl'),
          $fieldsContainer = this.$('#hustle-form-fields-container');
      field = _.extend({}, this.getFieldViewDefaults(field.type), field);

      if (-1 !== jQuery.inArray(field.type, ['gdpr', 'recaptcha'])) {
        this.$('#hustle-optin-field--' + field.type).removeClass('sui-hidden');
        $('#hustle-optin-insert-field--' + field.type).prop('checked', true).prop('disabled', true);
      } else if (null === oldFieldName) {
        $fieldsContainer.append(template(field));
      } else {
        var $el = this.$('#hustle-optin-field--' + oldFieldName);

        if (0 < $el.length) {
          $el.after(template(field));
        } else {
          $fieldsContainer.append(template(field));
        }
      }
    },
    getNewFieldId: function getNewFieldId(fieldName) {
      var existingFields = Object.assign({}, this.model.get('form_elements'));
      var fieldId = fieldName;

      while (fieldId in existingFields && -1 === jQuery.inArray(fieldId, ['gdpr', 'recaptcha', 'submit'])) {
        fieldId = fieldName + '-' + Math.floor(Math.random() * 99);
      }

      return fieldId;
    },

    /**
     * Retrieve the default settings for each field type.
     * These are going to be stored.
     *
     * @since 4.0.0
     *
     * @param {string} fieldType The type of the field we're getting the defaults for.
     */
    getFieldDefaults: function getFieldDefaults(fieldType) {
      var fieldId = this.getNewFieldId(fieldType),
          defaults = {
        label: optinVars.form_fields.label[fieldType + '_label'],
        required: 'false',
        css_classes: '',
        type: fieldType,
        name: fieldId,
        required_error_message: optinVars.form_fields.required_error_message.replace('{field}', fieldType),
        validation_message: optinVars.form_fields.validation_message.replace('{field}', fieldType),
        placeholder: ''
      };

      switch (fieldType) {
        case 'timepicker':
          defaults.time_format = '12'; // eslint-disable-line camelcase

          defaults.time_hours = '9'; // eslint-disable-line camelcase

          defaults.time_minutes = '30'; // eslint-disable-line camelcase

          defaults.time_period = 'am'; // eslint-disable-line camelcase

          defaults.validation_message = optinVars.form_fields.time_validation_message; // eslint-disable-line camelcase

          defaults.required_error_message = optinVars.form_fields.is_required.replace('{field}', defaults.label); // eslint-disable-line camelcase

          defaults.validate = 'false';
          break;

        case 'datepicker':
          defaults.date_format = 'mm/dd/yy'; // eslint-disable-line camelcase

          defaults.validation_message = optinVars.form_fields.date_validation_message; // eslint-disable-line camelcase

          defaults.required_error_message = optinVars.form_fields.is_required.replace('{field}', defaults.label); // eslint-disable-line camelcase

          defaults.validate = 'false';
          break;

        case 'recaptcha':
          defaults.threshold = '0.5'; // eslint-disable-line camelcase

          defaults.version = 'v2_checkbox'; // eslint-disable-line camelcase

          defaults.recaptcha_type = 'compact'; // eslint-disable-line camelcase

          defaults.recaptcha_theme = 'light'; // eslint-disable-line camelcase

          defaults.v2_invisible_theme = 'light'; // eslint-disable-line camelcase

          defaults.recaptcha_language = 'automatic'; // eslint-disable-line camelcase

          defaults.v2_invisible_show_badge = '1'; // eslint-disable-line camelcase

          defaults.v2_invisible_badge_replacement = optinVars.form_fields.recaptcha_badge_replacement; // eslint-disable-line camelcase

          defaults.v3_recaptcha_show_badge = '1'; // eslint-disable-line camelcase

          defaults.v3_recaptcha_badge_replacement = optinVars.form_fields.recaptcha_badge_replacement; // eslint-disable-line camelcase

          defaults.validation_message = optinVars.form_fields.recaptcha_validation_message; // eslint-disable-line camelcase

          defaults.error_message = optinVars.form_fields.recaptcha_error_message; // eslint-disable-line camelcase

          break;

        case 'gdpr':
          defaults.gdpr_message = optinVars.form_fields.gdpr_message; // eslint-disable-line camelcase

          defaults.required = 'true';
          defaults.required_error_message = optinVars.form_fields.gdpr_required_error_message; // eslint-disable-line camelcase

          break;

        case 'email':
          defaults.validate = 'true';
          break;

        case 'url':
          defaults.required_error_message = optinVars.form_fields.url_required_error_message; // eslint-disable-line camelcase

          defaults.validate = 'true';
          break;

        case 'phone':
          defaults.validate = 'false';
          break;

        case 'hidden':
          defaults.default_value = 'user_ip'; // eslint-disable-line camelcase

          defaults.custom_value = ''; // eslint-disable-line camelcase

          break;

        case 'number':
        case 'text':
          defaults.required_error_message = optinVars.form_fields.cant_empty; // eslint-disable-line camelcase

          break;
      }

      return defaults;
    },

    /**
     * Retrieve the defaults for each field type's setting view.
     * These settings are intended to display the proper content of each field
     * in the wizard settings. These won't be stored.
     *
     * @since 4.0.0
     * @param {string} fieldType The field type.
     */
    getFieldViewDefaults: function getFieldViewDefaults(fieldType) {
      var defaults = {
        required: 'false',
        validated: 'false',
        placeholder_placeholder: optinVars.form_fields.label.placeholder,
        label_placeholder: '',
        name_placeholder: '',
        icon: 'send',
        css_classes: '',
        type: fieldType,
        name: fieldType,
        placeholder: optinVars.form_fields.label[fieldType + '_placeholder'],
        can_delete: true,
        fieldId: this.getNewFieldId(fieldType)
      };

      switch (fieldType) {
        case 'email':
          defaults.icon = 'mail';
          break;

        case 'name':
          defaults.icon = 'profile-male';
          break;

        case 'phone':
          defaults.icon = 'phone';
          break;

        case 'address':
          defaults.icon = 'pin';
          break;

        case 'url':
          defaults.icon = 'web-globe-world';
          break;

        case 'text':
          defaults.icon = 'style-type';
          break;

        case 'number':
          defaults.icon = 'element-number';
          break;

        case 'timepicker':
          defaults.icon = 'clock';
          break;

        case 'datepicker':
          defaults.icon = 'calendar';
          break;

        case 'recaptcha':
          defaults.icon = 'recaptcha';
          break;

        case 'gdpr':
          defaults.icon = 'gdpr';
          break;

        case 'hidden':
          defaults.icon = 'eye-hide';
          break;
      }

      return defaults;
    }
  });
});
Hustle.define('Module.IntegrationsView', function ($) {
  'use strict';

  var integrationsView = Hustle.View.extend(_.extend({}, Hustle.get('Mixins.Model_Updater'), {
    el: '#hustle-box-section-integrations',
    events: {
      'click .connect-integration': 'connectIntegration',
      'keypress .connect-integration': 'preventEnterKeyFromDoingThings'
    },
    init: function init(opts) {
      this.model = new opts.BaseModel(optinVars.current.integrations_settings || {});
      this.moduleId = optinVars.current.data.module_id;
      this.listenTo(this.model, 'change', function (model) {
        return Hustle.Events.trigger('modules.view.integrationsUpdate', model);
      });
      this.listenTo(Hustle.Events, 'hustle:providers:reload', this.renderProvidersTables);
      this.render();
    },
    render: function render() {
      var $notConnectedWrapper = this.$el.find('#hustle-not-connected-providers-section'),
          $connectedWrapper = this.$el.find('#hustle-connected-providers-section');

      if (0 < $notConnectedWrapper.length && 0 < $connectedWrapper.length) {
        this.renderProvidersTables();
      }
    },
    renderProvidersTables: function renderProvidersTables() {
      var self = this,
          data = {}; // Add preloader.

      this.$el.find('.hustle-integrations-display').html("<div class=\"sui-notice hustle-integration-loading-notice\">\n\t\t\t\t\t\t<div class=\"sui-notice-content\">\n\t\t\t\t\t\t\t<div class=\"sui-notice-message\">\n\n\t\t\t\t\t\t\t\t<span class=\"sui-notice-icon sui-icon-loader sui-loading sui-md\" aria-hidden=\"true\"></span>\n\t\t\t\t\t\t\t\t<p>".concat(optinVars.integrations.fetching_list, "</p>\n\n\t\t\t\t\t\t\t</div>\n\t\t\t\t\t\t</div>\n\t\t\t\t\t</div>"));
      data.action = 'hustle_provider_get_form_providers';
      data._ajax_nonce = optinVars.integrations.action_nonce; // eslint-disable-line camelcase

      data.data = {
        moduleId: this.moduleId
      };
      var ajax = $.post({
        url: ajaxurl,
        type: 'post',
        data: data
      }).done(function (result) {
        if (result && result.success) {
          var $activeIntegrationsInput = self.$el.find('#hustle-integrations-active-integrations'),
              $activeIntegrationsCount = self.$el.find('#hustle-integrations-active-count');
          self.$el.find('#hustle-not-connected-providers-section').html(result.data.not_connected);
          self.$el.find('#hustle-connected-providers-section').html(result.data.connected); // Prevent marking the model as changed on load.

          if ($activeIntegrationsInput.val() !== result.data.list_connected) {
            $activeIntegrationsInput.val(result.data.list_connected).trigger('change');
          } // Prevent marking the model as changed on load.


          if ($activeIntegrationsCount.val() !== String(result.data.list_connected_total)) {
            $activeIntegrationsCount.val(result.data.list_connected_total).trigger('change');
          }
        }
      }); // Remove preloader

      ajax.always(function () {
        self.$el.find('.sui-box-body').removeClass('sui-block-content-center');
        self.$el.find('.hustle-integration-loading-notice').remove();
      });
    },
    // Prevent the enter key from opening integrations modals and breaking the page.
    preventEnterKeyFromDoingThings: function preventEnterKeyFromDoingThings(e) {
      if (13 === e.which) {
        // the enter key code
        e.preventDefault();
      }
    },
    connectIntegration: function connectIntegration(e) {
      Module.integrationsModal.open(e);
    }
  }));
  return integrationsView;
});
function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

Hustle.define('Mixins.Module_Visibility', function ($) {
  'use strict';

  return _.extend({}, Hustle.get('Mixins.Model_Updater'), {
    el: '#hustle-conditions-group',
    events: {
      'click .hustle-add-new-visibility-group': 'addNewGroup',
      'click .hustle-choose-conditions': 'openConditionsModal',
      'click .hustle-remove-visibility-group': 'removeGroup',
      'change .visibility-group-filter-type': 'updateAttribute',
      'change .visibility-group-show-hide': 'updateAttribute',
      'change .visibility-group-apply-on': 'updateGroupApplyOn'
    },
    init: function init(opts) {
      var Model = opts.BaseModel.extend({
        defaults: {
          conditions: ''
        },
        initialize: function initialize(data) {
          _.extend(this, data);

          if (!(this.get('conditions') instanceof Backbone.Model)) {
            /**
             * Make sure conditions is not an array
             */
            if (_.isEmpty(this.get('conditions')) && _.isArray(this.get('conditions'))) {
              this.conditions = {};
            }

            var hModel = Hustle.get('Model');
            this.set('conditions', new hModel(this.conditions), {
              silent: true
            });
          }
        }
      });
      this.model = new Model(optinVars.current.visibility || {});
      this.moduleType = optinVars.current.data.module_type;
      this.activeConditions = {};
      this.render();
      $('#hustle-general-conditions').on('click', $.proxy(this.switchConditions, this));
      $('#hustle-wc-conditions').on('click', $.proxy(this.switchConditions, this));
      this.groupId = '';
    },
    render: function render() {
      var self = this,
          groups = this.model.get('conditions').toJSON();

      if (!$.isEmptyObject(groups)) {
        for (var groupId in groups) {
          var group = this.model.get('conditions.' + groupId);

          if (!(group instanceof Backbone.Model)) {
            // Make sure it's not an array
            if (_.isEmpty(group) && _.isArray(group)) {
              group = {};
            }

            group = this.getConditionsGroupModel(group);
            self.model.set('conditions.' + groupId, group, {
              silent: true
            });
          }

          this.addGroupToPanel(group, 'render');
        }

        this.maybeToggleGroupsBin();
      } else {
        this.addNewGroup();
      }
    },
    afterRender: function afterRender() {
      this.bindRemoveConditions();
    },
    bindRemoveConditions: function bindRemoveConditions() {
      // Remove condition
      $('#hustle-conditions-group .hustle-remove-visibility-condition').off('click').on('click', $.proxy(this.removeCondition, this));
    },
    openConditionsModal: function openConditionsModal(e) {
      var self = this,
          $this = $(e.currentTarget),
          groupId = $this.data('group-id'),
          savedConditions = this.model.get('conditions.' + groupId),
          groupConditions = 'undefined' !== typeof savedConditions ? Object.keys(savedConditions.toJSON()) : [],
          VisibilityModalView = Hustle.get('Modals.Visibility_Conditions'),
          visibilityModal = new VisibilityModalView({
        groupId: groupId,
        conditions: groupConditions
      });
      visibilityModal.on('conditions:added', $.proxy(self.addNewConditions, self));
      this.groupId = groupId; // Show dialog.

      SUI.openModal('hustle-dialog--visibility-options', $this[0], this.$('#hustle-dialog--visibility-options .sui-box-header .sui-button-icon')[0], true);
    },
    addNewConditions: function addNewConditions(args) {
      var self = this,
          groupId = args.groupId,
          conditions = args.conditions,
          group = this.model.get('conditions.' + groupId);
      $.each(conditions, function (i, id) {
        if (group.get(id)) {
          // If this condition is already set for this group, abort. Prevent duplicated conditions in a group.
          return true;
        }

        self.addConditionToPanel(id, {}, groupId, group, 'new');
      });
      this.bindRemoveConditions();
      Hustle.Events.trigger('view.rendered', this);
    },
    addGroupToPanel: function addGroupToPanel(group, source) {
      // Render this group container.
      var groupId = group.get('group_id'),
          targetContainer = $('#hustle-visibility-conditions-box'),
          _template = Optin.template('hustle-visibility-group-box-tpl'),
          html = _template(_.extend({}, {
        groupId: groupId,
        apply_on_floating: group.get('apply_on_floating'),
        // eslint-disable-line camelcase
        apply_on_inline: group.get('apply_on_inline'),
        // eslint-disable-line camelcase
        apply_on_widget: group.get('apply_on_widget'),
        // eslint-disable-line camelcase
        apply_on_shortcode: group.get('apply_on_shortcode'),
        // eslint-disable-line camelcase
        show_or_hide_conditions: group.get('show_or_hide_conditions'),
        // eslint-disable-line camelcase
        filter_type: group.get('filter_type') // eslint-disable-line camelcase

      }));

      var $group = $(html);
      $group.insertBefore(targetContainer.find('.hustle-add-new-visibility-group'));
      SUI.select.init($group.find('.sui-select'));
      this.activeConditions[groupId] = {}; // Render each of this group's conditions.

      var self = this,
          conditions = group.toJSON();
      $.each(conditions, function (id, condition) {
        if ('object' !== _typeof(condition)) {
          // If this property is not an actual condition, like "group_id", or "filter_type",
          // continue. Check the next property as this isn't the condition we want to render.
          return true;
        }

        self.addConditionToPanel(id, condition, groupId, group, source);
      });
    },
    addConditionToPanel: function addConditionToPanel(id, condition, groupId, group, source) {
      if ('undefined' === typeof Optin.View.Conditions[id]) {
        return;
      }

      var thisCondition = new Optin.View.Conditions[id]({
        type: this.moduleType,
        model: group,
        groupId: groupId,
        source: source
      });

      if (!thisCondition) {
        return;
      }

      var $conditionsContainer = this.$('#hustle-visibility-group-' + groupId + ' .sui-box-builder-body'); // If there aren't other conditions rendered within the group, empty it for adding new conditions.

      if (!$conditionsContainer.find('.sui-builder-field').length) {
        $conditionsContainer.find('.sui-box-builder-message-block').hide();
        $conditionsContainer.find('.sui-button-dashed').show();
      }

      if ($.isEmptyObject(condition)) {
        group.set(id, thisCondition.getConfigs());
      } else {
        group.set(id, condition);
      }

      this.activeConditions[groupId][id] = thisCondition;
      $(thisCondition.$el).appendTo($conditionsContainer.find('.sui-builder-fields'));
      return thisCondition;
    },
    addNewGroup: function addNewGroup() {
      var group = this.getConditionsGroupModel(),
          groupId = group.get('group_id');
      this.model.set('conditions.' + groupId, group);
      this.addGroupToPanel(group, 'new');
      this.maybeToggleGroupsBin();
      Hustle.Events.trigger('view.rendered', this);
    },
    switchConditions: function switchConditions(e) {
      e.preventDefault();
      var $this = $(e.currentTarget),
          currentId = $this.prop('id');

      if ('hustle-wc-conditions' === currentId) {
        $('#hustle-dialog--visibility-options .general_condition').hide();
        $('#hustle-dialog--visibility-options .wc_condition').show();
      } else {
        $('#hustle-dialog--visibility-options .wc_condition').hide();
        $('#hustle-dialog--visibility-options .general_condition').show();
      }
    },
    removeGroup: function removeGroup(e) {
      var groupId = $(e.currentTarget).data('group-id'),
          $groupContainer = this.$('#hustle-visibility-group-' + groupId); // Remove the group from the model.

      delete this.activeConditions[groupId];
      this.model.get('conditions').unset(groupId); // Remove the group container from the page.

      $groupContainer.remove(); // If the last group was removed, add a new group so the page is not empty.

      if (!Object.keys(this.activeConditions).length) {
        this.addNewGroup();
      }

      this.maybeToggleGroupsBin();
    },
    removeCondition: function removeCondition(e) {
      var $this = $(e.currentTarget),
          conditionId = $this.data('condition-id'),
          groupId = $this.data('group-id'),
          $conditionsContainer = this.$('#hustle-visibility-group-' + groupId + ' .sui-box-builder-body'),
          thisCondition = this.activeConditions[groupId][conditionId];
      thisCondition.remove();
      delete this.activeConditions[groupId][conditionId];
      this.model.get('conditions.' + groupId).unset(conditionId);

      if (!$conditionsContainer.find('.sui-builder-field').length) {
        $conditionsContainer.find('.sui-box-builder-message-block').show();
      }

      this.bindRemoveConditions();
    },
    updateAttribute: function updateAttribute(e) {
      e.stopPropagation();
      var $this = $(e.target),
          groupId = $this.data('group-id'),
          attribute = $this.data('group-attribute'),
          value = $this.val(),
          group = this.model.get('conditions.' + groupId);
      group.set(attribute, value);
    },
    updateGroupApplyOn: function updateGroupApplyOn(e) {
      e.stopPropagation();
      var $this = $(e.target),
          groupId = $this.data('group-id'),
          attribute = $this.data('property'),
          value = $this.is(':checked'),
          group = this.model.get('conditions.' + groupId);

      if ('embedded' === this.moduleType && -1 !== $.inArray(attribute, ['apply_on_inline', 'apply_on_widget', 'apply_on_shortcode']) || 'social_sharing' === this.moduleType && -1 !== $.inArray(attribute, ['apply_on_floating', 'apply_on_inline', 'apply_on_widget', 'apply_on_shortcode'])) {
        group.set(attribute, value);
      }
    },
    getConditionsGroupModel: function getConditionsGroupModel(group) {
      if (!group) {
        var groupId = new Date().getTime().toString(16);

        if ('undefined' !== typeof this.model.get('conditions.' + groupId)) {// TODO: create another group_id while the group id exists.
        }

        group = {
          group_id: groupId,
          // eslint-disable-line camelcase
          show_or_hide_conditions: 'show',
          // eslint-disable-line camelcase
          filter_type: 'all' // eslint-disable-line camelcase

        };

        if ('embedded' === this.moduleType) {
          group.apply_on_inline = true; // eslint-disable-line camelcase

          group.apply_on_widget = true; // eslint-disable-line camelcase

          group.apply_on_shortcode = false; // eslint-disable-line camelcase
        } else if ('social_sharing' === this.moduleType) {
          group.apply_on_floating = true; // eslint-disable-line camelcase

          group.apply_on_inline = true; // eslint-disable-line camelcase

          group.apply_on_widget = true; // eslint-disable-line camelcase

          group.apply_on_shortcode = false; // eslint-disable-line camelcase
        }
      } else if ('embedded' === this.moduleType && (!group.apply_on_inline || !group.apply_on_widget || !group.apply_on_shortcode)) {
        if (!group.apply_on_inline) {
          group.apply_on_inline = true; // eslint-disable-line camelcase
        }

        if (!group.apply_on_widget) {
          group.apply_on_widget = true; // eslint-disable-line camelcase
        }

        if (!group.apply_on_shortcode) {
          group.apply_on_shortcode = false; // eslint-disable-line camelcase
        }
      } else if ('social_sharing' === this.moduleType && (!group.apply_on_floating || !group.apply_on_inline || !group.apply_on_widget || !group.apply_on_shortcode)) {
        if (!group.apply_on_floating) {
          group.apply_on_floating = true; // eslint-disable-line camelcase
        }

        if (!group.apply_on_inline) {
          group.apply_on_inline = true; // eslint-disable-line camelcase
        }

        if (!group.apply_on_widget) {
          group.apply_on_widget = true; // eslint-disable-line camelcase
        }

        if (!group.apply_on_shortcode) {
          group.apply_on_shortcode = false; // eslint-disable-line camelcase
        }
      }

      var hModel = Hustle.get('Model'),
          groupModel = new hModel(group);
      return groupModel;
    },

    /**
     * Prevent the last standing group from being removable
     * Enable again the "bin" icons to remove if there's more than 1 group.
     *
     * @since 4.1.0
     */
    maybeToggleGroupsBin: function maybeToggleGroupsBin() {
      var groups = this.model.get('conditions'),
          $groupsBin = $('#hustle-conditions-group .sui-box-builder-header .hustle-remove-visibility-group');

      if (1 === Object.keys(groups.toJSON()).length) {
        Module.Utils.accessibleHide($groupsBin);
      } else {
        Module.Utils.accessibleShow($groupsBin);
      }
    }
  });
});
/* global tinyMCE */
Hustle.define('Mixins.Wizard_View', function ($, doc, win) {
  'use strict';

  return {
    moduleType: '',
    el: '.sui-wrap-hustle',
    publishModal: {},
    previewView: null,
    events: {
      'click .sui-sidenav .sui-vertical-tab a': 'sidenav',
      'change select.sui-mobile-nav': 'sidenavMobile',
      'click a.hustle-go-to-tab': 'sidenav',
      'click a.notify-error-tab': 'sidenav',
      'click .hustle-action-save': 'saveChanges',
      'click .wpmudev-button-navigation': 'doButtonNavigation',
      'change #hustle-module-name': 'updateModuleName',
      'click #hustle-preview-module': 'previewModule',
      'blur input.sui-form-control': 'removeErrorMessage',
      // Module's actions.
      'click .hustle-single-module-button-action': 'handleSingleModuleAction'
    },
    // ============================================================
    // Initialize Wizard
    init: function init(opts) {
      var _this = this;

      this.setTabsViews(opts);
      Hustle.Events.on('modules.view.switch_status', function (switchTo) {
        return _this.switchStatusTo(switchTo);
      });
      $(win).off('popstate', $.proxy(this.updateTabOnPopstate, this));
      $(win).on('popstate', $.proxy(this.updateTabOnPopstate, this));
      $(document).off('tinymce-editor-init', $.proxy(this.tinymceReady, this));
      $(document).on('tinymce-editor-init', $.proxy(this.tinymceReady, this));

      if ('undefined' !== typeof this._events) {
        this.events = $.extend(true, {}, this.events, this._events);
        this.delegateEvents();
      }

      var publishModal = Hustle.get('Modals.PublishFlow');
      this.publishModal = new publishModal();
      this.renderTabs();
      return this;
    },

    /**
     * Assign the tabs views to the object.
     * Overridden by social share.
     *
     * @param {Object} opts Views for each tab.
     */
    setTabsViews: function setTabsViews(opts) {
      this.contentView = opts.contentView;
      this.emailsView = opts.emailsView;
      this.designView = opts.designView;
      this.integrationsView = opts.integrationsView;
      this.visibilityView = opts.visibilityView;
      this.settingsView = opts.settingsView;
      this.moduleType = this.model.get('module_type');

      if ('embedded' === this.moduleType) {
        this.displayView = opts.displayView;
      }
    },
    // ============================================================
    // Render content

    /**
     * Render the tabs.
     * Overridden by social share.
     */
    renderTabs: function renderTabs() {
      // Content view
      this.contentView.delegateEvents(); // Emails view

      this.emailsView.delegateEvents(); // Integrations view

      this.integrationsView.delegateEvents(); // Appearance view

      this.designView.delegateEvents(); // Display Options View

      if ('embedded' === this.moduleType) {
        this.displayView.delegateEvents();
      } // Visibility view


      this.visibilityView.delegateEvents();
      this.visibilityView.afterRender(); // Behavior view

      this.settingsView.delegateEvents();
    },
    // ============================================================
    // Side Navigation
    sidenav: function sidenav(e) {
      e.preventDefault();
      var tabName = $(e.target).data('tab');

      if (tabName) {
        this.goToTab(tabName, true);
      }
    },
    sidenavMobile: function sidenavMobile(e) {
      var tabName = $(e.currentTarget).val();

      if (tabName) {
        this.goToTab(tabName, true);
      }
    },
    goToTab: function goToTab(tabName, updateHistory) {
      var $tab = this.$el.find('a[data-tab="' + tabName + '"]'),
          $sidenav = $tab.closest('.sui-vertical-tabs'),
          $tabs = $sidenav.find('.sui-vertical-tab a'),
          $content = this.$el.find('.sui-box[data-tab]'),
          $current = this.$el.find('.sui-box[data-tab="' + tabName + '"]');

      if (updateHistory) {
        // The module id must be defined at this point.
        // If it's not, the user should be redirected to the listing page to properly create a module before reaching this.
        var state = {
          tabName: tabName
        },
            moduleId = this.model.get('module_id');
        history.pushState(state, 'Hustle ' + this.moduleType + ' wizard', 'admin.php?page=' + optinVars.current.wizard_page + '&id=' + moduleId + '&section=' + tabName);
      }

      $tabs.removeClass('current');
      $content.hide();
      $tab.addClass('current');
      $current.show();
      $('.sui-wrap-hustle')[0].scrollIntoView();
    },
    // Keep the sync of the shown tab and the URL when going "back" with the browser.
    updateTabOnPopstate: function updateTabOnPopstate(e) {
      var state = e.originalEvent.state;

      if (state) {
        this.goToTab(state.tabName);
      }
    },
    // Go to he "next" and "previous" tab when using the buttons at the bottom of the wizard.
    doButtonNavigation: function doButtonNavigation(e) {
      e.preventDefault();
      var $button = $(e.target),
          direction = 'prev' === $button.data('direction') ? 'prev' : 'next',
          nextTabName = this.getNextOrPrevTabName(direction);
      this.goToTab(nextTabName, true);
    },
    // Get the name of the previous or next tab.
    getNextOrPrevTabName: function getNextOrPrevTabName(direction) {
      var current = $('#hustle-module-wizard-view .sui-sidenav ul li a.current');
      var tab = current.data('tab');

      if ('prev' === direction) {
        tab = current.parent().prev().find('a').data('tab');
      } else {
        tab = current.parent().next().find('a').data('tab');
      }

      return tab;
    },
    // ============================================================
    // TinyMCE
    // Set the editor content in their respective model on change.
    tinymceReady: function tinymceReady(e, editor) {
      var _this2 = this;

      editor.on('change', function () {
        var model = 'main_content' === editor.id ? _this2.contentView.model : _this2.emailsView.model;
        model.set(editor.id, editor.getContent());
      });
    },
    setContentFromTinymce: function setContentFromTinymce() {
      var keepSilent = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : false;

      if ('social_sharing' !== this.moduleType && 'undefined' !== typeof tinyMCE) {
        // main_content editor
        var mainContentEditor = tinyMCE.get('main_content'),
            $mainContentTextarea = this.$('textarea#main_content'),
            mainContent = 'true' === $mainContentTextarea.attr('aria-hidden') ? mainContentEditor.getContent() : $mainContentTextarea.val();
        this.contentView.model.set('main_content', mainContent, {
          silent: keepSilent
        }); // success_message editor

        var successMessageEditor = tinyMCE.get('success_message'),
            $successMessageTextarea = this.$('textarea#success_message'),
            successMessage = 'true' === $successMessageTextarea.attr('aria-hidden') ? successMessageEditor.getContent() : $successMessageTextarea.val();
        this.emailsView.model.set('success_message', successMessage, {
          silent: keepSilent
        }); // email_body editor

        var emailBodyEditor = tinyMCE.get('email_body'),
            $emailBodyTextarea = this.$('textarea#email_body'),
            emailBody = 'true' === $successMessageTextarea.attr('aria-hidden') ? emailBodyEditor.getContent() : $emailBodyTextarea.val();
        this.emailsView.model.set('email_body', emailBody, {
          silent: keepSilent
        });
      }
    },
    // ============================================================
    // Sanitize Data
    sanitizeData: function sanitizeData() {
      // Call to action
      var ctaUrl = this.contentView.model.get('cta_url');

      if (0 !== ctaUrl.indexOf('mailto:') && 0 !== ctaUrl.indexOf('tel:')) {
        if (!/^(f|ht)tps?:\/\//i.test(ctaUrl)) {
          ctaUrl = 'https://' + ctaUrl;
          this.contentView.model.set('cta_url', ctaUrl, {
            silent: true
          });
        }
      }
    },
    // ============================================================
    // Save changes
    save: function save() {
      this.setContentFromTinymce(true);
      this.sanitizeData(); // Preparig the data

      var $this = this.$el.find('#hustle-module-wizard-view'),
          id = $this.data('id'),
          nonce = $this.data('nonce'),
          module = this.model.toJSON();
      var data = {
        action: 'hustle_save_module',
        _ajax_nonce: nonce,
        id: id,
        module: module
      };

      _.extend(data, this.getDataToSave()); // ajax save here


      return $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data,
        dataType: 'json'
      });
    },
    getDataToSave: function getDataToSave() {
      var data = {
        content: this.contentView.model.toJSON(),
        emails: this.emailsView.model.toJSON(),
        design: this.designView.updatedProperties,
        // this.designView.model.toJSON(),
        integrations_settings: this.integrationsView.model.toJSON(),
        // eslint-disable-line camelcase
        visibility: this.visibilityView.model.toJSON(),
        settings: JSON.stringify(this.settingsView.model.toJSON())
      }; // We overwrite the Custom CSS value straight from the editor.

      data.design.custom_css = this.designView.cssEditor.getValue(); // eslint-disable-line camelcase

      if ('embedded' === this.moduleType) {
        data.display = this.displayView.model.toJSON();
      }

      return data;
    },
    saveChanges: function saveChanges(e) {
      var _this3 = this;

      e.preventDefault();
      var currentActive = this.model.get('active'),
          $saveButton = $(e.currentTarget),
          setActiveTo = String($saveButton.data('active')),
          activeChanged = setActiveTo !== currentActive,
          wasPublished = '0' !== setActiveTo;
      this.disableButtonsOnSave($saveButton);

      if (activeChanged && wasPublished) {
        this.publishModal.open();
      }

      this.model.set('active', setActiveTo, {
        silent: true
      });
      var save = this.save(); // TODO: handle errors. Like when the nonce expired.

      save.done(function (res) {
        if (true === res.success) {
          // The changes were already saved.
          Module.hasChanges = false; // Change the "Pending changes" label to "Saved".

          _this3.switchStatusTo('saved');

          if (activeChanged) {
            if (wasPublished) {
              // Ssharing modules don't have schedules.
              var isScheduled = 'social_sharing' !== _this3.model.get('module_type') ? '1' === _this3.settingsView.model.get('is_schedule') : false;
              var hasEnd = false; // Handle the 'published' modal messages according to the schedule.

              if (isScheduled) {
                var scheduleSettings = _this3.settingsView.model.get('schedule');

                hasEnd = '1' !== scheduleSettings.not_schedule_end;
              }

              _this3.publishModal.setPublished(isScheduled, hasEnd);
            }

            _this3.updateViewOnActiveChange();
          }
        } else {
          var errors = res.data;
          var errorMessage = ''; // When nonce expired or something we didn't thought about happened errors.data is not defined
          // so it's a place to inform the user that he should reload his browser.

          if ('undefined' === typeof errors.data) {
            errorMessage = optinVars.messages.module_error_reload;
          } else {
            if ('undefined' !== typeof errors.data.icon_error) {
              _.each(errors.data.icon_error, function (error) {
                $('#hustle-platform-' + error).find('.sui-error-message').show();
                $('#hustle-platform-' + error + ' .hustle-social-url-field').addClass('sui-form-field-error');
                $('#hustle-platform-' + error).not('.sui-accordion-item--open').find('.sui-accordion-open-indicator').click();
              });

              errorMessage = '<a href="#" data-tab="services" class="notify-error-tab"> ' + optinVars.module_tabs.services + ' </a>';
            } else if ('undefined' !== typeof errors.data.selector_error) {
              _.each(errors.data.selector_error, function (error) {
                $('input[name="' + error + '_css_selector"]').siblings('.sui-error-message').show();
                $('input[name="' + error + '_css_selector"]').parent('.sui-form-field').addClass('sui-form-field-error');
              });

              if (!_.isEmpty(errorMessage)) {
                errorMessage = errorMessage + ' and ';
              }

              errorMessage = errorMessage + '<a href="#" data-tab="display" class="notify-error-tab"> ' + optinVars.module_tabs.display + ' </a>';
            }

            errorMessage = optinVars.messages.module_error.replace('{page}', errorMessage);
          }

          _this3.switchStatusTo('unsaved');

          Module.Notification.open('error', errorMessage, false);
        }
      }).always(function () {
        _this3.enableSaveButtons();
      });
    },
    // ============================================================
    // Update the view elements

    /**
     * Update this module's name if the new value is not empty.
     *
     * @param {event} e Event.
     */
    updateModuleName: function updateModuleName(e) {
      var $input = $(e.target),
          moduleName = $input.val();

      if (moduleName.length) {
        this.$('#hustle-module-name-wrapper').removeClass('sui-form-field-error');
        this.$('#hustle-module-name-error').hide();
        this.$('#hustle-module-name-error').html('');
        this.model.set('module_name', moduleName);
      } else {
        var message = this.$('#hustle-module-name-error').data('error-message');
        this.$('#hustle-module-name-wrapper').addClass('sui-form-field-error');
        this.$('#hustle-module-name-error').html(message);
        this.$('#hustle-module-name-error').show();
      }
    },
    // Disable the save buttons.
    disableButtonsOnSave: function disableButtonsOnSave($buttonOnLoad) {
      $buttonOnLoad.addClass('sui-button-onload');
      this.$('.hustle-action-save').prop('disabled', true);
      this.$('.wpmudev-button-navigation').prop('disabled', true);
    },
    // Enable the save buttons.
    enableSaveButtons: function enableSaveButtons() {
      this.$('.sui-button-onload').removeClass('sui-button-onload');
      this.$('.hustle-action-save').prop('disabled', false);
      this.$('.wpmudev-button-navigation').prop('disabled', false);
    },
    // Change the 'saved'/'unsaved' label.
    switchStatusTo: function switchStatusTo(switchTo) {
      if ('saved' === switchTo) {
        this.$el.find('#hustle-unsaved-changes-status').addClass('sui-hidden');
        this.$el.find('#hustle-saved-changes-status').removeClass('sui-hidden');
      } else {
        this.$el.find('#hustle-unsaved-changes-status').removeClass('sui-hidden');
        this.$el.find('#hustle-saved-changes-status').addClass('sui-hidden');
      }
    },
    // Change the 'Draft'/'Published' module status label, and update the save buttons for each case.
    updateViewOnActiveChange: function updateViewOnActiveChange() {
      var isActive = '1' === this.model.get('active'); // Update the module status tag. The one that says if the module is Published or a Draft.

      var $statusTag = this.$('.sui-status-module .sui-tag'),
          newStatus = isActive ? optinVars.messages.commons.published : optinVars.messages.commons.draft;
      $statusTag.text(newStatus);

      if (isActive) {
        $statusTag.addClass('sui-tag-blue');
      } else {
        $statusTag.removeClass('sui-tag-blue');
      }

      var saveDraftContent = this.$('#hustle-draft-button-save-draft-text'),
          unpublishContent = this.$('#hustle-draft-button-unpublish-text'); // Update the text of buttons for publishing and unpublishing the module.

      if (isActive) {
        saveDraftContent.addClass('sui-hidden-important');
        unpublishContent.removeClass('sui-hidden-important');
      } else {
        saveDraftContent.removeClass('sui-hidden-important');
        unpublishContent.addClass('sui-hidden-important');
      } // Update the text within the Publish button.


      var $publishButton = this.$('.hustle-publish-button'),
          publishButtonText = isActive ? $publishButton.data('update') : $publishButton.data('publish');
      $publishButton.find('.button-text').text(publishButtonText);
    },
    removeErrorMessage: function removeErrorMessage(e) {
      if (e.target.value) {
        var parent = $(e.target).parent('.sui-form-field');
        parent.removeClass('sui-form-field-error');
        parent.find('.sui-error-message').hide();
      }
    },
    // ============================================================
    // Previewing
    previewModule: function previewModule(e) {
      e.preventDefault();
      var $button = $(e.currentTarget);
      this.setContentFromTinymce(true);
      this.sanitizeData();

      var previewData = _.extend({}, this.model.toJSON(), this.getDataToSave()),
          moduleName = previewData.module_name.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

      previewData.module_name = moduleName;
      this.getPreviewView().open(this.model.get('module_id'), this.model.get('module_type'), $button, previewData);
    },
    getPreviewView: function getPreviewView() {
      if (!this.previewView) {
        var previewView = Hustle.get('Modals.Preview');
        this.previewView = new previewView();
      }

      return this.previewView;
    },
    // ============================================================
    // Module's actions.
    handleSingleModuleAction: function handleSingleModuleAction(e) {
      Module.handleActions.initAction(e, 'listing', this);
    }
  };
});
Hustle.define('Settings.Palettes', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#palettes-box',
    events: {
      'click .hustle-create-palette': 'openCreatePaletteModal',
      'click .hustle-delete-button': 'openDeletePaletteModal',
      'click .hustle-button-delete': 'delettePalette'
    },
    initialize: function initialize() {
      var PaletteModal = Hustle.get('Settings.Palettes_Modal');
      this.paletteModal = new PaletteModal();
    },
    openCreatePaletteModal: function openCreatePaletteModal(e) {
      this.paletteModal.open(e);
    },
    openDeletePaletteModal: function openDeletePaletteModal(e) {
      e.preventDefault();
      var $this = $(e.currentTarget),
          data = {
        id: $this.data('id'),
        title: $this.data('title'),
        description: $this.data('description'),
        action: 'delete',
        nonce: $this.data('nonce'),
        actionClass: 'hustle-button-delete'
      };
      Module.deleteModal.open(data, $this[0]); // This element is outside the view and only added after opening the modal.

      $('.hustle-button-delete').on('click', $.proxy(this.delettePalette, this));
    },

    /**
     * Handle the color palettes 'delete' action.
     *
     * @since 4.0.3
     * @param {Object} e
     */
    delettePalette: function delettePalette(e) {
      e.preventDefault();
      var $this = $(e.currentTarget),
          relatedFormId = $this.data('form-id'),
          actionData = $this.data(),
          $form = $('#' + relatedFormId),
          data = new FormData($form[0]); // TODO: remove when "hustle_action" field name is changed to "hustleAction"

      $.each(actionData, function (name, value) {
        return data.append(name, value);
      });
      data.append('_ajax_nonce', optinVars.settings_palettes_action_nonce);
      data.append('action', 'hustle_handle_palette_actions');
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data,
        contentType: false,
        processData: false
      }).done(function (res) {
        if (res.data.url) {
          location.replace(res.data.url);
        } else if (res.data.notification) {
          Module.Notification.open(res.data.notification.status, res.data.notification.message, res.data.notification.delay);
        } // Don't remove the 'loading' icon when redirecting/reloading.


        if (!res.data.url) {
          $('.sui-button-onload').removeClass('sui-button-onload');
        }
      }).fail(function () {
        Module.Notification.open('error', optinVars.messages.commons.generic_ajax_error);
        $('.sui-button-onload').removeClass('sui-button-onload');
      });
    }
  });
});
Hustle.define('Settings.Data_Settings', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#data-box',
    events: {
      'click #hustle-dialog-open--reset-data-settings': 'dataDialog'
    },
    // ============================================================
    // DIALOG: Reset Settings
    // Open dialog
    dataDialog: function dataDialog(e) {
      e.preventDefault();
      var $button = this.$(e.target),
          $dialog = $('#hustle-dialog--reset-data-settings');
      SUI.openModal('hustle-dialog--reset-data-settings', $button[0], $dialog.find('.sui-box-header .sui-button-icon')[0], true);
      $('#hustle-reset-settings').off('click').on('click', $.proxy(this.settingsReset));
    },
    // Confirm and close
    settingsReset: function settingsReset(e) {
      var $this = $(e.currentTarget),
          $dialog = $this.closest('.sui-modal'),
          $buttons = $dialog.find('button, .sui-button');
      $buttons.prop('disabled', true);
      $this.addClass('sui-button-onload');
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: {
          action: 'hustle_reset_settings',
          _ajax_nonce: $this.data('nonce') // eslint-disable-line camelcase

        },
        success: function success() {
          $('#' + $this.data('notice')).show();
          SUI.closeModal();
          $this.removeClass('sui-button-onload');
          $buttons.prop('disabled', false);
          Module.Notification.open('success', optinVars.messages.settings_was_reset);
          window.setTimeout(function () {
            return location.reload(true);
          }, 2000);
        },
        error: function error() {
          SUI.closeModal();
          $this.removeClass('sui-button-onload');
          $buttons.prop('disabled', false);
          Module.Notification.open('error', optinVars.messages.something_went_wrong);
        }
      });
    }
  });
});
Hustle.define('Settings.Palettes_Modal', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-dialog--edit-palette',
    events: {
      'click .hustle-button-action': 'handleAction',
      'click .hustle-modal-close': 'closeCreatePaletteModal',
      'change #hustle-palette-module-type': 'updateModulesOptions'
    },
    initialize: function initialize() {},
    open: function open(e) {
      var slug = $(e.currentTarget).data('slug');

      if ('undefined' !== typeof slug) {
        // When editing a palette.
        this.handleAction(e);
      } else {
        // When creating a new palette.
        // Update the modules' options when opening.
        this.$('#hustle-palette-module-type').trigger('change');
        SUI.openModal('hustle-dialog--edit-palette', e.currentTarget, 'hustle-palette-name', false);
      }
    },

    /**
     * Handle the color palettes 'save' action.
     *
     * @since 4.0.3
     * @param {Object} e
     */
    handleAction: function handleAction(e) {
      e.preventDefault();
      var self = this,
          $this = $(e.currentTarget),
          relatedFormId = $this.data('form-id');
      $this.addClass('sui-button-onload');
      Module.Utils.accessibleHide(this.$('.sui-error-message'));
      var data = new FormData(),
          errors = false; // Grab the form's data if the action has a related form.

      if ('undefined' !== typeof relatedFormId) {
        var $form = $('#' + relatedFormId);

        if ($form.length) {
          data = new FormData($form[0]);
          $form.find('.hustle-required-field').each(function (i, el) {
            var $field = $(el);

            if (!$field.val().trim().length) {
              var errorMessage = $field.data('error-message'),
                  $errorMessage = $field.siblings('.sui-error-message');
              $errorMessage.html(errorMessage);
              Module.Utils.accessibleShow($errorMessage);
              errors = true;
            }
          });
        }
      } // Don't do the request if there are missing required fields.


      if (errors) {
        $('.sui-button-onload').removeClass('sui-button-onload');
        return;
      }

      var actionData = $this.data();
      $.each(actionData, function (name, value) {
        return data.append(name, value);
      });
      data.append('_ajax_nonce', optinVars.settings_palettes_action_nonce);
      data.append('action', 'hustle_handle_palette_actions');
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data,
        contentType: false,
        processData: false
      }).done(function (res) {
        // If there's a defined callback, call it.
        if (res.data.callback && 'function' === typeof self[res.data.callback]) {
          // This calls the "action{ hustle action }" functions from this view.
          // For example: actionToggleStatus();
          self[res.data.callback](res.data, res.success, e);
        } else if (res.data.url) {
          location.replace(res.data.url);
        } else if (res.data.notification) {
          Module.Notification.open(res.data.notification.status, res.data.notification.message, res.data.notification.delay);
        } // Don't remove the 'loading' icon when redirecting/reloading.


        if (!res.data.url) {
          $('.sui-button-onload').removeClass('sui-button-onload');
        }
      }).fail(function () {
        $('.sui-button-onload').removeClass('sui-button-onload');
      });
    },
    actionOpenEditPalette: function actionOpenEditPalette(data, success, e) {
      this.actionGoToSecondStep(data);
      SUI.openModal('hustle-dialog--edit-palette', e.currentTarget, 'hustle-palette-name', false);

      if (data.palette_data.name) {
        $('#hustle-dialog--edit-palette').find('#hustle-palette-name').val(data.palette_data.name);
      }
    },
    actionGoToSecondStep: function actionGoToSecondStep(data) {
      var stepOne = this.$('#hustle-edit-palette-first-step'),
          stepTwo = this.$('#hustle-edit-palette-second-step'),
          btnAction = this.$('.hustle-button-action'),
          paletteData = data.palette_data,
          template = Optin.template('hustle-dialog--edit-palette-tpl'); // Hide first step

      Module.Utils.accessibleHide(stepOne, true); // Print and show second step

      stepTwo.html(template(paletteData));
      this.initiateSecondStepElements();
      Module.Utils.accessibleShow(stepTwo, true);
      stepTwo.focus(); // Set new step

      btnAction.data('step', 3);
      btnAction.addClass('sui-button-blue');
      Module.Utils.accessibleHide(btnAction.find('#hustle-step-button-text'));
      Module.Utils.accessibleShow(btnAction.find('#hustle-finish-button-text'));
    },
    initiateSecondStepElements: function initiateSecondStepElements() {
      // Accordions.
      this.$('.sui-accordion').each(function () {
        SUI.suiAccordion(this);
      }); // Init tabs

      SUI.suiTabs();
      SUI.tabs(); // Color pickers.

      this.createPickers();
    },
    closeCreatePaletteModal: function closeCreatePaletteModal() {
      var self = this,
          stepOne = this.$('#hustle-edit-palette-first-step'),
          stepTwo = this.$('#hustle-edit-palette-second-step'),
          btnAction = this.$('.hustle-button-action');
      setTimeout(function () {
        // Hide error messages
        Module.Utils.accessibleHide(self.$('.sui-error-message')); // Hide second step

        Module.Utils.accessibleHide(stepTwo, true);
        stepTwo.html(''); // Show first step

        Module.Utils.accessibleShow(stepOne, true); // Reset action button

        btnAction.removeClass('sui-button-blue');
        btnAction.data('step', 2);
        Module.Utils.accessibleShow(btnAction.find('#hustle-step-button-text'));
        Module.Utils.accessibleHide(btnAction.find('#hustle-finish-button-text'));
      }, 500);
    },
    // ============================================================
    // Color Pickers
    // TODO: Copied from wizards. Re-use instead of copy-pasting
    createPickers: function createPickers() {
      var $suiPickerInputs = this.$('.sui-colorpicker-input');
      $suiPickerInputs.wpColorPicker({
        change: function change(event, ui) {
          var $this = $(this); // Prevent the model from being marked as changed on load.

          if ($this.val() !== ui.color.toCSS()) {
            $this.val(ui.color.toCSS()).trigger('change');
          }
        },
        palettes: ['#333333', '#FFFFFF', '#17A8E3', '#E1F6FF', '#666666', '#AAAAAA', '#E6E6E6']
      });

      if ($suiPickerInputs.hasClass('wp-color-picker')) {
        $suiPickerInputs.each(function () {
          var $suiPickerInput = $(this),
              $suiPicker = $suiPickerInput.closest('.sui-colorpicker-wrap'),
              $suiPickerColor = $suiPicker.find('.sui-colorpicker-value span[role=button]'),
              $suiPickerValue = $suiPicker.find('.sui-colorpicker-value'),
              $suiPickerClear = $suiPickerValue.find('button'),
              $shownInput = $suiPickerValue.find('.hustle-colorpicker-input');
          var $wpPicker = $suiPickerInput.closest('.wp-picker-container'),
              $wpPickerButton = $wpPicker.find('.wp-color-result'),
              $wpPickerAlpha = $wpPickerButton.find('.color-alpha'),
              $wpPickerClear = $wpPicker.find('.wp-picker-clear');
          var $suiPickerType = 'hex'; // Check if alpha exists

          if (true === $suiPickerInput.data('alpha')) {
            $suiPickerType = 'rgba'; // Listen to color change

            $suiPickerInput.on('change', function () {
              // Change color preview
              $suiPickerColor.find('span').css({
                'background-color': $wpPickerAlpha.css('background')
              }); // We trigger this 'change' manually when the shown input changes.
              // Don't update its value again if this is the case.

              if ('undefined' === typeof data) {
                // Change color value
                $shownInput.val($suiPickerInput.val());
              }
            });
          } else {
            // Listen to color change
            $suiPickerInput.on('change', function () {
              // Change color preview
              $suiPickerColor.find('span').css({
                'background-color': $wpPickerButton.css('background-color')
              }); // We trigger this 'change' manually when the shown input changes.
              // Don't update its value again if this is the case.

              if ('undefined' === typeof data) {
                // Change color value
                $shownInput.val($suiPickerInput.val());
              }
            });
          } // Allow updating the colors without having to open the colorpicker.


          $shownInput.on('change', function () {
            // Change color value
            $suiPickerInput.val($shownInput.val());
            $suiPickerInput.trigger('change', [{
              triggeredByUs: true
            }]);
          }); // Add picker type class

          $suiPicker.find('.sui-colorpicker').addClass('sui-colorpicker-' + $suiPickerType); // Open iris picker

          $suiPicker.find('.sui-button, span[role=button]').on('click', function (e) {
            $wpPickerButton.click();
            e.preventDefault();
            e.stopPropagation();
          }); // Clear color value

          $suiPickerClear.on('click', function (e) {
            var inputName = $suiPickerInput.data('attribute'),
                selectedStyle = $('#hustle-palette-module-fallback').val(),
                resetValue = optinVars.palettes[selectedStyle][inputName];
            $wpPickerClear.click();
            $suiPickerValue.find('input').val(resetValue);
            $suiPickerInput.val(resetValue).trigger('change');
            $suiPickerColor.find('span').css({
              'background-color': resetValue
            });
            e.preventDefault();
            e.stopPropagation();
          });
        });
      }
    },
    updateModulesOptions: function updateModulesOptions(e) {
      var $this = $(e.currentTarget),
          self = this,
          moduleType = $this.val(),
          $modulesOptionsSelect = this.$('#hustle-palette-module-name');
      var html = '';
      $.each(optinVars.current[moduleType], function (id, name) {
        html += "<option value=\"".concat(id, "\">").concat(name, "</option>");
      });
      $modulesOptionsSelect.html(html);
      this.$('.sui-select:not(.hustle-select-ajax)').SUIselect2({
        dropdownCssClass: 'sui-select-dropdown',
        dropdownParent: self.$('.sui-box')
      });
    }
  });
});
Hustle.define('Settings.Permissions_View', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#permissions-box',
    initialize: function initialize() {
      $(function () {
        //Delete the remove ability for Administrator option in select2
        function blockingAdminRemove() {
          $('.select2-selection__rendered li:first-child .select2-selection__choice__remove').off('click').text('').on('click', function (e) {
            e.stopImmediatePropagation();
            e.preventDefault();
          });
        }

        $('select').on('change.select2', function () {
          blockingAdminRemove();
        });
        blockingAdminRemove();
      });
    }
  });
});
Hustle.define('Settings.Privacy_Settings', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#privacy-box',
    events: {
      'click #hustle-dialog-open--delete-ips': 'openDeleteIpsDialog'
    },
    initialize: function initialize() {
      $('#hustle-delete-ips-submit').on('click', this.handleIpDeletion);
    },
    // ============================================================
    // DIALOG: Delete All IPs
    // Open dialog
    openDeleteIpsDialog: function openDeleteIpsDialog(e) {
      SUI.openModal('hustle-dialog--delete-ips', $(e.currentTarget)[0], this.$('#hustle-dialog--delete-ips .sui-box-header .sui-button-icon')[0], true);
      e.preventDefault();
    },
    handleIpDeletion: function handleIpDeletion(e) {
      e.preventDefault();
      var $this = $(e.currentTarget),
          $form = $('#' + $this.data('formId')),
          data = new FormData($form[0]);
      data.append('action', 'hustle_remove_ips');
      data.append('_ajax_nonce', $this.data('nonce'));
      $this.addClass('sui-button-onload');
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data,
        contentType: false,
        processData: false,
        success: function success(res) {
          Module.Notification.open('success', res.data.message);
          SUI.closeModal();
          $('.sui-button-onload').removeClass('sui-button-onload');
        },
        error: function error() {
          SUI.closeModal();
          $('.sui-button-onload').removeClass('sui-button-onload');
          Module.Notification.open('error', optinVars.messages.something_went_wrong);
        }
      });
    }
  });
});
Hustle.define('Settings.reCaptcha_Settings', function ($) {
  'use strict';

  return Backbone.View.extend({
    el: '#recaptcha-box',
    data: {},
    initialize: function initialize() {
      this.maybeRenderRecaptchas();
    },
    maybeRenderRecaptchas: function maybeRenderRecaptchas() {
      var _this = this;

      var self = this,
          versions = ['v2_checkbox', 'v2_invisible', 'v3_recaptcha'];
      var scriptAdded = false;

      var _loop = function _loop() {
        var version = _versions[_i];

        var $previewContainer = _this.$("#hustle-modal-recaptcha-".concat(version, "-0")),
            sitekey = _this.$("input[name=\"".concat(version, "_site_key\"]")).val().trim(),
            secretkey = _this.$("input[name=\"".concat(version, "_secret_key\"]")).val().trim();

        if (sitekey && secretkey) {
          $previewContainer.data('sitekey', sitekey);

          if (!scriptAdded) {
            $.ajax({
              url: ajaxurl,
              type: 'POST',
              data: {
                action: 'hustle_load_recaptcha_preview'
              }
            }).done(function (result) {
              if (result.success) {
                scriptAdded = true;
                self.$('#hustle-recaptcha-script-container').html(result.data);
                setTimeout(function () {
                  return HUI.maybeRenderRecaptcha($previewContainer.closest('.sui-form-field'));
                }, 1000);
              }
            });
          } else {
            HUI.maybeRenderRecaptcha($previewContainer.closest('.sui-form-field'));
          }

          _this.$(".hustle-recaptcha-".concat(version, "-preview-notice")).hide();

          $previewContainer.show();
        } else {
          _this.$(".hustle-recaptcha-".concat(version, "-preview-notice")).show();

          $previewContainer.hide();
        }
      };

      for (var _i = 0, _versions = versions; _i < _versions.length; _i++) {
        _loop();
      }
    }
  });
});
Hustle.define('Settings.Top_Metrics_View', function () {
  'use strict';

  return Backbone.View.extend({
    el: '#top-metrics-box',
    events: {
      'click .sui-checkbox input': 'maybeDisableInputs'
    },
    initialize: function initialize() {
      this.maybeDisableInputs();
    },
    maybeDisableInputs: function maybeDisableInputs() {
      var $allchecked = this.$el.find('input:checked'),
          $unchecked = this.$el.find('input:not(:checked)'),
          $button = this.$el.find('button[type="submit"]'),
          $buttonTip = $button.parent(),
          $design = $unchecked.next('span');

      if (3 <= $allchecked.length) {
        $unchecked.prop('disabled', true);
        $design.addClass('sui-tooltip');
        $design.css('opacity', '1');
        $button.prop('disabled', false);
        $buttonTip.removeClass('sui-tooltip');
      } else {
        $button.prop('disabled', true);
        $unchecked.prop('disabled', false);
        $design.removeClass('sui-tooltip');
        $design.css('opacity', '');
        $buttonTip.addClass('sui-tooltip');
      }
    }
  });
});
Hustle.define('Integration_Modal_Handler', function ($) {
  'use strict';

  return Backbone.View.extend({
    events: {
      'click .hustle-provider-connect': 'connectAddOn',
      'click .hustle-provider-disconnect': 'disconnectAddOn',
      'click .hustle-provider-next': 'submitNextStep',
      'click .hustle-provider-back': 'goPrevStep',
      'click .hustle-refresh-email-lists': 'refreshLists',
      'click .hustle-provider-form-disconnect': 'disconnectAddOnForm',
      'click .hustle-provider-clear-radio-options': 'clearRadioOptions',
      'change select#group': 'showInterests'
    },
    initialize: function initialize(options) {
      var _this = this;

      this.slug = options.slug;
      this.nonce = options.nonce;
      this.action = options.action; // eslint-disable-next-line camelcase

      this.moduleId = options.moduleId; // eslint-disable-next-line camelcase

      this.multi_id = options.multiId;
      this.globalMultiId = options.globalMultiId;
      this.step = 0; // eslint-disable-next-line camelcase

      this.next_step = false; // eslint-disable-next-line camelcase

      this.prev_step = false; // Attach close actions to SUI's modal close event.

      this.$el.off('close').on('close', function () {
        return _this.modalClosed();
      });
      return this.render();
    },
    render: function render() {
      var data = {};
      data.action = this.action; // eslint-disable-next-line camelcase

      data._ajax_nonce = this.nonce;
      data.data = {};
      data.data.slug = this.slug;
      data.data.step = this.step; // eslint-disable-next-line camelcase

      data.data.current_step = this.step;

      if (this.moduleId) {
        // eslint-disable-next-line camelcase
        data.data.module_id = this.moduleId;
      }

      if (this.multi_id) {
        // eslint-disable-next-line camelcase
        data.data.multi_id = this.multi_id;
      }

      if (this.globalMultiId) {
        // eslint-disable-next-line camelcase
        data.data.global_multi_id = this.globalMultiId;
      }

      this.request(data, false, true);
    },
    applyLoader: function applyLoader($element) {
      $element.find('.sui-button:not(.disable-loader)').addClass('sui-button-onload');
    },
    resetLoader: function resetLoader($element) {
      $element.find('.sui-button').removeClass('sui-button-onload');
    },
    request: function request(data, close, loader) {
      var self = this;

      if (loader) {
        this.$el.find('.sui-box-body').addClass('sui-block-content-center').html( // TODO: translate "loading content".
        '<p class="sui-loading-dialog" aria-label="Loading content"><i class="sui-icon-loader sui-loading" aria-hidden="true"></i></p>');
        this.$el.find('.sui-box-footer').html('');
        this.$el.find('.integration-header').html('');
      }

      this.applyLoader(this.$el);
      this.ajax = $.post({
        url: ajaxurl,
        type: 'post',
        data: data
      }).done(function (result) {
        if (result && result.success) {
          // Shorten result data
          var resultData = result.data.data; // Handle close modal

          if (close || !_.isUndefined(resultData.is_close) && resultData.is_close) {
            SUI.closeModal();
          } else {
            // Render popup body
            self.renderBody(result); // Render popup footer

            self.renderFooter(result);
            self.onRender(resultData);
            self.resetLoader(self.$el);
          } // Handle notifications


          if (!_.isUndefined(resultData.notification) && !_.isUndefined(resultData.notification.type) && !_.isUndefined(resultData.notification.text)) {
            var custom = Module.Notification;
            custom.open(resultData.notification.type, resultData.notification.text);
          } // Handle the modal's size.


          if (!_.isUndefined(resultData.size)) {
            var $modal = self.$el.closest('.sui-modal'); // Remove all sizes

            if (resultData.size === 'normal') {
              $modal.removeClass('sui-modal-sm sui-modal-lg');
            }

            if (resultData.size === 'small') {
              $modal.addClass('sui-modal-sm');
              $modal.removeClass('sui-modal-lg');
            }

            if (resultData.size === 'large') {
              $modal.addClass('sui-modal-lg');
              $modal.removeClass('sui-modal-sm');
            }
          } // Show Mailchimp interests is Group is already choosen


          if ('mailchimp' === self.slug) {
            var group = self.$el.find('#group');

            if (group.length) {
              group.trigger('change');
            }
          } // There's a response, but not a successful one.

        } else {
          // Render popup body
          self.renderBody(result); // Render popup footer

          self.renderFooter(result);
        }
      }); // Remove the preloader

      this.ajax.always(function (result) {
        // Add closing event.
        self.$el.find('.hustle-modal-close').off('click').on('click', function () {
          SUI.closeModal();
        });
        self.$el.find('.sui-box-body').removeClass('sui-block-content-center');
        self.$el.find('.sui-loading-dialog').remove();

        if (!result || !result.success || !result.data) {
          self.showGenericErrorMessage();
        }
      });
    },
    renderBody: function renderBody(result) {
      if (!result.data || !result.data.data) {
        return;
      }

      this.$el.find('.sui-box-body').html(result.data.data.html); // append header to integration-header

      var integrationHeader = this.$el.find('.sui-box-body .integration-header').remove();

      if (0 < integrationHeader.length) {
        this.$el.find('.integration-header').html(integrationHeader.html());
      } // Hide empty content


      if (!this.$el.find('.sui-box-body').html().trim().length) {
        this.$el.find('.sui-box-body').addClass('sui-hidden');
        this.$el.find('.sui-box-footer').css('padding-top', '');
      } else {
        var children = this.$el.find('.sui-box-body').children();
        var hideBody = true;
        $.each(children, function (i, child) {
          if (!$(child).is(':hidden')) {
            hideBody = false;
          }
        }); // Hide the content only when all children are hidden.

        if (hideBody) {
          this.$el.find('.sui-box-body').addClass('sui-hidden');
          this.$el.find('.sui-box-footer').css('padding-top', '');
        } else {
          // FIX: Prevent extra spacing.
          // eslint-disable-next-line no-lonely-if
          if (this.$el.find('.sui-box-body .sui-notice').next().is('input[type="hidden"]')) {
            this.$el.find('.sui-box-body .sui-notice').css({
              'margin-bottom': '0'
            });
          }
        }
      }
    },
    renderFooter: function renderFooter(result) {
      if (!result.data || !result.data.data) {
        return;
      }

      var self = this,
          buttons = result.data.data.buttons,
          body = self.$el.find('.sui-box-body'),
          footer = self.$el.find('.sui-box-footer'); // Clear the body's spacing classes.

      body.removeClass('sui-spacing-bottom--0').removeClass('sui-spacing-bottom--30'); // Clear footer from previous buttons

      footer.removeClass('sui-hidden').removeClass('sui-hidden-important').removeClass('sui-content-center').removeClass('sui-content-right').removeClass('sui-content-separated').html(''); // Append buttons

      _.each(buttons, function (button) {
        footer.append(button.markup);
      });

      if (0 === footer.find('.sui-button').length) {
        footer.addClass('sui-hidden-important');
        body.addClass('sui-spacing-bottom--30');
      } else {
        // The footer is shown. It has the required spacing.
        body.addClass('sui-spacing-bottom--0'); // FIX: Align buttons to center.

        if (footer.find('.sui-button').hasClass('sui-button-center')) {
          footer.addClass('sui-content-center'); // FIX: Align buttons to right.
        } else if (footer.find('.sui-button').hasClass('sui-button-right')) {
          if (!footer.find('.sui-button').hasClass('sui-button-left')) {
            footer.addClass('sui-content-right');
          } // FIX: Align buttons separated.

        } else {
          footer.addClass('sui-content-separated');
        }
      }
    },
    onRender: function onRender(result) {
      var self = this;
      this.delegateEvents(); // Update current step

      if (!_.isUndefined(result.opt_in_provider_current_step)) {
        this.step = +result.opt_in_provider_current_step;
      } // Update has next step


      if (!_.isUndefined(result.opt_in_provider_has_next_step)) {
        // eslint-disable-next-line camelcase
        this.next_step = result.opt_in_provider_has_next_step;
      } // Update has prev step


      if (!_.isUndefined(result.opt_in_provider_has_prev_step)) {
        // eslint-disable-next-line camelcase
        this.prev_step = result.opt_in_provider_has_prev_step;
      }

      self.$el.find('.sui-select').SUIselect2({
        dropdownCssClass: 'sui-select-dropdown',
        dropdownParent: $('#hustle-integration-dialog .sui-box')
      });
    },
    refreshLists: function refreshLists(e) {
      var _this2 = this;

      e.preventDefault();
      e.stopPropagation();
      var $this = $(e.currentTarget),
          $oldSelect = $('#list_id').length ? $('#list_id') : $('#form_id'),
          id = this.moduleId,
          slug = this.slug,
          type = $('#form_id').length ? 'forms' : 'lists',
          nonce = this.nonce;
      $this.addClass('sui-button-onload');
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: {
          action: 'hustle_refresh_email_lists',
          id: id,
          slug: slug,
          type: type,
          _ajax_nonce: nonce // eslint-disable-line camelcase

        }
      }).done(function (result) {
        if (result.success) {
          if ('undefined' !== typeof result.data.select) {
            var $refreshContainer = $oldSelect.closest('.hui-select-refresh');
            $oldSelect.SUIselect2('destroy');
            $oldSelect.remove();
            var $newSelect = $(result.data.select);
            $refreshContainer.prepend($newSelect);
            $newSelect.SUIselect2({
              dropdownParent: _this2.$('.sui-box'),
              dropdownCssClass: 'sui-select-dropdown'
            });
          }
        }
      }).fail(function () {// TODO: handle errors
      }).always(function () {
        $this.removeClass('sui-button-onload');
      });
    },
    submitNextStep: function submitNextStep() {
      var data = {},
          form = this.$el.find('form'),
          params = {
        slug: this.slug,
        step: this.getStep(),
        // eslint-disable-next-line camelcase
        current_step: this.step
      };
      var formData = form.serialize();

      if (this.moduleId) {
        // eslint-disable-next-line camelcase
        params.module_id = this.moduleId;
      }

      formData = formData + '&' + $.param(params);
      data.action = this.action; // eslint-disable-next-line camelcase

      data._ajax_nonce = this.nonce;
      data.data = formData;
      this.request(data, false, false);
    },
    goPrevStep: function goPrevStep() {
      var data = {},
          params = {
        slug: this.slug,
        step: this.getPrevStep(),
        current_step: this.step
      };

      if (this.moduleId) {
        // eslint-disable-next-line camelcase
        params.module_id = this.moduleId;
      }

      if (this.multi_id) {
        // eslint-disable-next-line camelcase
        params.multi_id = this.multi_id;
      }

      data.action = this.action; // eslint-disable-next-line camelcase

      data._ajax_nonce = this.nonce;
      data.data = params;
      this.request(data, false, false);
    },
    getStep: function getStep() {
      if (this.next_step) {
        return this.step + 1;
      }

      return this.step;
    },
    getPrevStep: function getPrevStep() {
      if (this.prev_step) {
        return this.step - 1;
      }

      return this.step;
    },
    connectAddOn: function connectAddOn() {
      var data = {},
          form = this.$el.find('form'),
          params = {
        slug: this.slug,
        step: this.getStep(),
        // eslint-disable-next-line camelcase
        current_step: this.step
      };
      var formData = form.serialize();

      if (this.moduleId) {
        // eslint-disable-next-line camelcase
        params.module_id = this.moduleId;
      }

      if (this.multi_id) {
        // eslint-disable-next-line camelcase
        params.multi_id = this.multi_id;
      }

      formData = formData + '&' + $.param(params);
      data.action = this.action; // eslint-disable-next-line camelcase

      data._ajax_nonce = this.nonce;
      data.data = formData;
      this.request(data, false, false);
    },
    disconnectAddOn: function disconnectAddOn() {
      var self = this,
          img = this.$el.find('.sui-box-logo img').attr('src'),
          title = this.$el.find('#dialogTitle2').html(),
          data = {},
          isActiveData = {};
      var modules = {};
      data.action = 'hustle_provider_deactivate'; // eslint-disable-next-line camelcase

      data._ajax_nonce = this.nonce;
      data.data = {};
      data.data.slug = this.slug;
      data.data.img = img;
      data.data.title = title;

      if (this.globalMultiId) {
        // eslint-disable-next-line camelcase
        data.data.global_multi_id = this.globalMultiId;
      }

      isActiveData.action = 'hustle_provider_is_on_module'; // eslint-disable-next-line camelcase

      isActiveData._ajax_nonce = this.nonce;
      isActiveData.data = {};
      isActiveData.data.slug = this.slug;
      isActiveData.data.globalMultiId = this.globalMultiId;
      this.$el.find('.sui-button:not(.disable-loader)').addClass('sui-button-onload');
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: isActiveData,
        success: function success(resp) {
          if (true === resp.success) {
            modules = resp;
          }
        },
        complete: function complete() {
          if (true === modules.success) {
            Module.integrationsActiveRemove.open(modules.data, data, self);
          } else {
            self.request(data, true, false);
          }
        }
      });
    },
    disconnectAddOnForm: function disconnectAddOnForm() {
      var self = this;
      var data = {};
      var active = $('#hustle-integrations-active-count').val(),
          activeIntegration = $('#hustle-integrations-active-integrations').val();
      data.action = 'hustle_provider_form_deactivate'; // eslint-disable-next-line camelcase

      data._ajax_nonce = this.nonce;
      data.data = {};
      data.data.slug = this.slug; // eslint-disable-next-line camelcase

      data.data.module_id = this.moduleId;

      if (this.multi_id) {
        // eslint-disable-next-line camelcase
        data.data.multi_id = this.multi_id;
      }

      if ('1' === active && activeIntegration === this.slug && 'local_list' !== this.slug) {
        Module.integrationsAllRemove.open(data, self);
      } else if ('1' === active && 'local_list' === this.slug) {
        Module.Notification.open('error', optinVars.messages.integraiton_required);
        SUI.closeModal();
      } else {
        this.request(data, true, false);
      }
    },
    modalClosed: function modalClosed() {
      // Kill AJAX hearbeat
      this.ajax.abort(); // Refrest add-on list

      Hustle.Events.trigger('hustle:providers:reload');
    },
    clearRadioOptions: function clearRadioOptions() {
      this.$('input[type=radio]', this.$el).prop('checked', false);
    },
    //show interests for mailchimp
    showInterests: function showInterests(e) {
      var self = this,
          $this = $(e.currentTarget),
          nonce = $this.data('nonce'),
          group = $this.val(),
          data = {},
          form = self.$el.find('form'),
          params = {
        slug: self.slug,
        group: group,
        module_id: self.moduleId
      };
      var formData = form.serialize();
      formData = formData + '&' + $.param(params);
      data.action = 'hustle_mailchimp_get_group_interests'; // eslint-disable-next-line camelcase

      data._ajax_nonce = nonce;
      data.data = formData;
      self.applyLoader(self.$el);
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data
      }).done(function (result) {
        if (result.success) {
          form.find('.sui-form-field').slice(1).remove();
          form.find('.sui-form-field:first-child').after(result.data);
        }
      }).fail(function () {// TODO: handle errors
      }).always(function () {
        self.resetLoader(self.$el);
      });
    },
    showGenericErrorMessage: function showGenericErrorMessage() {
      this.$el.find('.sui-box-body').html('<div id="hustle-request-error-reload-notice" role="alert" aria-live="assertive" class="sui-notice"></div>');
      this.$el.find('.sui-box-footer').html('');
      SUI.openNotice('hustle-request-error-reload-notice', '<p>' + optinVars.messages.request_error_reload_notice + '</p>', {
        type: "error",
        autoclose: {
          show: false
        }
      });
    }
  });
});
var Module = window.Module || {};
Hustle.define('Model', function ($) {
  'use strict';

  return Backbone.Model.extend({
    initialize: function initialize() {
      this.on('change', this.userHasChange, this);
      Backbone.Model.prototype.initialize.apply(this, arguments);
      $(window).on('beforeunload', this.changesNotSaved);
    },
    userHasChange: function userHasChange() {
      Module.hasChanges = true; // Add the "unsaved" status tag to the module screen.

      Hustle.Events.trigger('modules.view.switch_status', 'unsaved');
    },
    changesNotSaved: function changesNotSaved() {
      if (Module.hasChanges) {
        return 'You have unsaved changes'; // This message is ignored anyway.
      }
    }
  });
});
Hustle.define('Models.M', function () {
  'use strict';

  return Hustle.get('Model').extend({
    toJSON: function toJSON() {
      var json = _.clone(this.attributes);

      var attr;

      for (attr in json) {
        if (json[attr] instanceof Backbone.Model || json[attr] instanceof Backbone.Collection) {
          json[attr] = json[attr].toJSON();
        }
      }

      return json;
    },
    set: function set(key, val, options) {
      var parent, child, parentModel;

      if ('string' === typeof key && -1 !== key.indexOf('.')) {
        parent = key.split('.')[0];
        child = key.split('.')[1];
        parentModel = this.get(parent);

        if (parentModel && parentModel instanceof Backbone.Model) {
          parentModel.set(child, val, options);
          this.trigger('change:' + key, key, val, options);
          this.trigger('change:' + parent, key, val, options);
        }
      } else {
        Backbone.Model.prototype.set.call(this, key, val, options);
      }
    },
    get: function get(key) {
      var parent, child;

      if ('string' === typeof key && -1 !== key.indexOf('.')) {
        parent = key.split('.')[0];
        child = key.split('.')[1];
        return this.get(parent).get(child);
      }

      return Backbone.Model.prototype.get.call(this, key);
    }
  });
});
Hustle.define('Models.Trigger', function () {
  'use strict';

  return Hustle.get('Model').extend({
    defaults: {
      trigger: ['time'],
      // time | scroll | click | exit_intent | adblock
      on_time_delay: '0',
      on_time_unit: 'seconds',
      on_scroll: 'scrolled',
      // scrolled | selector
      on_scroll_page_percent: '20',
      on_scroll_css_selector: '',
      enable_on_click_element: '1',
      on_click_element: '',
      enable_on_click_shortcode: '1',
      on_exit_intent_per_session: '1',
      on_exit_intent_delayed_time: '5',
      on_exit_intent_delayed_unit: 'seconds',
      on_adblock_delay: '0',
      on_adblock_delay_unit: 'seconds'
    }
  });
});
Module.Model = Hustle.get('Models.M').extend({
  defaults: {
    module_name: '',
    moduleType: 'popup',
    active: '0'
  }
});
(function ($) {
  'use strict';
  /**
   * READ BEFORE ADDING A NEW OBJECT HERE.
   * This file should only contain *views* that are used in *more than one page*.
   * The idea is to have reusable views in a single place.
   * If the functionality you're about to introduce is used in a single page,
   * there's probably a specific view for that page, and its functionalities
   * should belong in there.
   *
   * For example:
   * Module's preview modal   => It's used in Dashboard, Listings, and Wizards. All good.
   * Module's tracking charts => It's only used in Listings. Not good.
   *                             There's a view for listings. It should be handled in the listing's view.
   */

  var Module = window.Module || {};
  /**
   * Render a notification at the top of the page.
   * Used in the global settings page when saving, for example.
   *
   * @since 4.0
   */

  Module.Notification = {
    id: null,
    $floatingContainer: null,
    open: function open(type, message) {
      var closeTime = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 4000;
      var id = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : 'hustle-only-active-notification';
      var isFloating = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : true;
      this.id = id;
      var options = {
        type: type || '',
        icon: 'info',
        // We're only using info icons atm.
        dismiss: {},
        autoclose: {}
      };

      if (isFloating) {
        this.$floatingContainer = $('#hustle-floating-notifications-wrapper');
        this.createFloatingNoticeWrapper(); // Make sure closeTime is an integer, unless it's false.

        if (false !== closeTime) {
          var parsedCloseTime = parseInt(closeTime); // Use the 4secs default otherwise.

          if (isNaN(parsedCloseTime)) {
            closeTime = 4000;
          }
        }

        options.dismiss = {
          show: false === closeTime,
          label: optinVars.messages.commons.dismiss
        };
        options.autoclose = {
          show: false !== closeTime,
          time: closeTime
        };
      } else {
        // We don't have auto-close nor dismissable inline notices.
        options.autoclose.show = false;
        options.dismiss.show = false;
      }

      message = "<p>".concat(message, "</p>");
      SUI.openNotice(id, message, options);
    },
    createFloatingNoticeWrapper: function createFloatingNoticeWrapper() {
      var id = this.id; // Create the notice wrapper if it doesn't exist already.

      if (!$('#' + id).length) {
        this.$floatingContainer.append("<div\n\t\t\t\t\trole=\"alert\"\n\t\t\t\t\tid=\"".concat(id, "\"\n\t\t\t\t\tclass=\"sui-notice\"\n\t\t\t\t\taria-live=\"assertive\"\n\t\t\t\t></div>"));
      }
    }
  };
  /**
   * Render the modal used for editing the itnegrations' settings.
   *
   * @since 4.0
   */

  Module.integrationsModal = {
    $popup: {},
    open: function open(e) {
      var self = this;
      var $target = $(e.target);

      if (!$target.hasClass('connect-integration')) {
        $target = $target.closest('.connect-integration');
      } // Remove the templated modal before adding a new one.


      if ($('#hustle-integration-dialog').closest('.sui-modal').length) {
        $('#hustle-integration-dialog').closest('.sui-modal').remove();
      }

      var nonce = $target.data('nonce'),
          slug = $target.data('slug'),
          title = $target.data('title'),
          image = $target.data('image'),
          action = $target.data('action'),
          moduleId = $target.data('module_id'),
          multiId = $target.data('multi_id'),
          globalMultiId = $target.data('global_multi_id'),
          tpl = Optin.template('hustle-integration-dialog-tpl');
      $('.sui-wrap-hustle').append(tpl({
        image: image,
        title: title
      }));
      this.$popup = $('#hustle-integration-dialog');
      var settingsView = Hustle.get('Integration_Modal_Handler');
      this.view = new settingsView({
        slug: slug,
        nonce: nonce,
        action: action,
        moduleId: moduleId,
        multiId: multiId,
        globalMultiId: globalMultiId,
        el: this.$popup
      });
      this.$popup.on('close', function () {
        return self.close();
      });
      SUI.openModal('hustle-integration-dialog', $target[0], this.$popup.find('.sui-box .hustle-modal-close')[0], true); // Make sui-tabs changeable

      this.$popup.on('click', '.sui-tab-item', function (ev) {
        var $this = $(ev.currentTarget),
            $items = $this.closest('.sui-side-tabs').find('.sui-tab-item');
        $items.removeClass('active');
        $this.addClass('active');
      });
    },
    close: function close() {
      if (this.view) {
        this.$popup.closest('.sui-modal').remove();
        this.view.remove();
      }
    }
  };
  /**
   * Handle the modal for when removing the only integration in a module.
   * In Wizard pages.
   *
   * @since 4.0.1
   */

  Module.integrationsAllRemove = {
    referrer: {},

    /**
     * @since 4.0.2
     * @param {Object} data
     * @param {Object} referrer
     */
    open: function open(data, referrer) {
      var self = this;
      this.referrer = referrer;
      var dialogId = $('#hustle-dialog--final-delete');

      var insertLocal = function insertLocal(insertData) {
        self.insertLocalList(insertData);
        return false;
      };

      var deleteInt = function deleteInt(deleteData, deleteReferrer) {
        self.deleteIntegration(deleteData, deleteReferrer);
        return false;
      };

      var $closeButton = dialogId.find('.sui-box-header .sui-button-icon'); // Add closing event

      $closeButton.on('click', self.close);
      dialogId.find('#hustle-delete-final-button-cancel').on('click', self.close);
      $('#hustle-delete-final-button').off('click').on('click', function () {
        $('#hustle-delete-final-button').addClass('sui-button-onload');
        deleteInt(data, referrer);
        insertLocal(data);
        self.close();
      });
      $('#hustle-delete-final-button').prop('disabled', false);
      var $providerConfigButton = $('#hustle-connected-providers-section button[data-slug="' + data.data.slug + '"]');
      SUI.replaceModal('hustle-dialog--final-delete', $providerConfigButton[0], $closeButton[0], true);
    },
    close: function close() {
      $('#hustle-delete-final-button').removeClass('sui-button-onload');
      $('#hustle-delete-final-button').prop('disabled', false);
    },
    confirmDelete: function confirmDelete(data, referrer) {
      this.deleteIntegration(data, referrer);
      this.insertLocal(data);
      this.close();
    },
    deleteIntegration: function deleteIntegration(data, referrer) {
      referrer.request(data, true, false);
    },
    insertLocalList: function insertLocalList(data) {
      var ajaxData = {
        id: data.data.module_id,
        _ajax_nonce: data._ajax_nonce,
        action: 'hustle_provider_insert_local_list'
      };
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: ajaxData,
        success: function success(resp) {
          if (resp.success) {
            Hustle.Events.trigger('hustle:providers:reload');
          } else {
            Module.Notification.open('error', optinVars.messages.something_went_wrong);
          }
        },
        error: function error() {
          Module.Notification.open('error', optinVars.messages.something_went_wrong);
        }
      });
    }
  };
  /**
   * Render the modal used when disconnecting a global integration that's in use in a module.
   * Used in the global Integrations page.
   *
   * @since 4.0.1
   */

  Module.integrationsActiveRemove = {
    $popup: {},
    _deferred: {},

    /**
     * @since 4.0.2
     * @param {Object} data
     * @param {Object} disconnect
     * @param {Object} referrer
     */
    open: function open(data, disconnect, referrer) {
      var self = this,
          dialogId = $('#hustle-dialog--remove-active');

      var goBack = function goBack() {
        self.back(referrer);
        return false;
      };

      var removeIntegration = function removeIntegration(integrationData, integrationReferrer, modules) {
        self.removeIntegration(integrationData, integrationReferrer, modules);
      };

      var tpl = Optin.template('hustle-modules-active-integration-tpl'),
          tplImg = Optin.template('hustle-modules-active-integration-img-tpl'),
          tplHead = Optin.template('hustle-modules-active-integration-header-tpl'),
          tplDesc = Optin.template('hustle-modules-active-integration-desc-tpl'); //remove previous html

      $('#hustle-dialog--remove-active tbody').html('');
      $('#hustle-dialog--remove-active .sui-box-logo').html('');
      $('#hustle-dialog--remove-active #hustle-dialog--remove-active-title').html('');
      $('#hustle-dialog--remove-active #hustle-dialog--remove-active-description').html('');
      $('#hustle-dialog--remove-active .sui-box-logo').append(tplImg({
        image: disconnect.data.img,
        title: disconnect.data.slug
      }));
      $('#hustle-dialog--remove-active #hustle-dialog--remove-active-title').append(tplHead({
        title: disconnect.data.title.replace(/Connect|Configure/gi, ' ')
      }));
      $('#hustle-dialog--remove-active #hustle-dialog--remove-active-description').append(tplDesc({
        title: disconnect.data.title.replace(/Connect|Configure/gi, ' ')
      }));
      $.each(data, function (id, meta) {
        $('#hustle-dialog--remove-active tbody').append(tpl({
          name: meta.name,
          type: meta.type,
          editUrl: meta.edit_url
        }));
      });
      dialogId.find('#hustle-remove-active-integration-back').off('click').on('click', function () {
        goBack();
      });
      $('#hustle-remove-active-button').off('click').on('click', function () {
        $(this).addClass('sui-button-onload');
        removeIntegration(disconnect, referrer, data);
      }); // Set the element to focus on once the modal is closed.

      var $configButton = '';

      if (referrer.globalMultiId) {
        $configButton = $('button[data-global_multi_id="' + referrer.globalMultiId + '"]');
      } else {
        $configButton = $('button[data-slug="' + disconnect.data.slug + '"]');
      }

      SUI.replaceModal('hustle-dialog--remove-active', $configButton[0], dialogId.find('.hustle-modal-close')[0], true);
    },
    close: function close() {
      SUI.closeModal();
    },
    back: function back(referrer) {
      var self = this;
      self.close(); //integrations that doesn't support global multi id.

      if ('hubspot' === referrer.slug || 'constantcontact' === referrer.slug || 'zapier' === referrer.slug) {
        $('button[data-slug="' + referrer.slug + '"]').trigger('click');
      } else {
        $('button[data-global_multi_id="' + referrer.globalMultiId + '"]').trigger('click');
      }
    },
    removeIntegration: function removeIntegration(data, referrer, modules) {
      var self = this;
      $.each(modules, function (id, meta) {
        if (data.data.slug === meta.active.active_integrations) {
          self.insertLocalList(data, id);
        }
      });
      referrer.request(data, true, false);
      $('#hustle-remove-active-button').removeClass('sui-button-onload');
    },
    insertLocalList: function insertLocalList(data, id) {
      var ajaxData = {
        id: id,
        _ajax_nonce: data._ajax_nonce,
        action: 'hustle_provider_insert_local_list'
      };
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: ajaxData,
        success: function success(resp) {
          if (false === resp.success) {
            Module.Notification.open('error', optinVars.messages.something_went_wrong);
          }
        },
        error: function error() {
          Module.Notification.open('error', optinVars.messages.something_went_wrong);
        }
      });
    }
  };
  /**
   * The provider migration model
   *
   * @since 4.0.3
   */

  Module.ProviderMigration = {
    $popup: {},

    /**
     * @since 4.0.3
     * @param {string} slug Provider slug.
     * @param {string} id Provider global multi ID.
     */
    open: function open(slug) {
      var id = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;

      var dialogId = $('#hustle-dialog-migrate--' + slug),
          self = this,
          reauthMultiID = function reauthMultiID() {
        var form = dialogId.find('form'),
            data = {},
            params = {
          slug: slug,
          // eslint-disable-next-line camelcase
          global_multi_id: id
        };
        var formData = form.serialize();
        $('#integration-migrate').addClass('sui-button-onload'); // eslint-disable-next-line camelcase

        data._ajax_nonce = $('#integration-migrate').data('nonce');
        data.action = 'hustle_provider_migrate_aweber';
        formData = formData + '&' + $.param(params);
        data.data = formData;
        self.reauth(dialogId, data, id, slug);
      };

      if (id) {
        $('#integration-migrate').attr('data-id', id);
      }

      setTimeout(function () {
        return SUI.openModal('hustle-dialog-migrate--' + slug, $('.sui-header-title')[0], $('#hustle-dialog-migrate--' + slug + ' .sui-box-header .sui-button-icon')[0], true);
      }, 300);
      dialogId.find('#integration-migrate').on('click', reauthMultiID);
    },
    reauth: function reauth(dialogId, data, id, slug) {
      var notice = $('.hustle_migration_notice__' + slug + '[data-id="' + id + '"]');
      this.ajax = $.post({
        url: ajaxurl,
        type: 'post',
        data: data
      }).done(function (result) {
        if (result && result.success) {
          SUI.closeModal();
          notice.hide();
          Module.Notification.open('success', optinVars.messages.aweber_migration_success, false);
        } else {
          $(dialogId).find('#integration-migrate').removeClass('sui-button-onload');
          $(dialogId).find('.sui-error-message').removeClass('sui-hidden');
          $(dialogId).find('.sui-form-field').addClass('sui-form-field-error');
        }
      });
    }
  };
  /**
   * The "are you sure?" modal from when deleting modules or entries.
   *
   * @since 4.0
   */

  Module.deleteModal = {
    /**
     * @since 4.0
     * @param {Object} data - Must contain 'title', 'description', 'nonce', 'action', and 'id' that's being deleted.
     * @param {Object} focusOnClose - Document node to focus on after the modal is closed.
     */
    open: function open(data, focusOnClose) {
      var dialogId = 'hustle-dialog--delete',
          template = Optin.template('hustle-dialog--delete-tpl'),
          content = template(data); // Add the templated content to the modal.

      $('#' + dialogId + ' #hustle-delete-dialog-content').html(content); // Add the title to the modal.

      $('#' + dialogId + ' #hustle-dialog--delete-title').html(data.title); // Attach the closing event.

      $('#' + dialogId + ' .hustle-cancel-button').on('click', function () {
        return SUI.closeModal(dialogId);
      });
      $('#' + dialogId + ' .hustle-delete-confirm').on('click', function (e) {
        var $button = $(e.currentTarget);
        $button.addClass('sui-button-onload');
      });
      SUI.openModal(dialogId, focusOnClose, $('#' + dialogId + '.hustle-modal-close')[0], true);
    }
  };
  /**
   * Key var to listen user changes before triggering
   * navigate away message.
   **/

  Module.hasChanges = false;
})(jQuery);
(function ($) {
  'use strict';

  var Module = window.Module || {};
  Module.Utils = {
    /*
     * Return URL param value
     */
    getUrlParam: function getUrlParam(param) {
      var defaultReturn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
      var urlParams = optinVars.urlParams;

      if ('undefined' !== typeof urlParams[param]) {
        return urlParams[param];
      }

      return defaultReturn;
    },
    accessibleHide: function accessibleHide($elements) {
      var isFocusable = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
      var extraToUpdate = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : false;
      $elements.hide();
      $elements.attr('aria-hidden', true);
      $elements.prop('hidden', true);

      if (isFocusable) {
        $elements.prop('tabindex', '-1');
      }

      if (extraToUpdate) {
        if ('undefined' !== typeof extraToUpdate.name) {
          if ('undefined' !== typeof extraToUpdate.value) {
            $elements.attr(extraToUpdate.name, extraToUpdate.value);
          } else {
            $elements.removeAttr(extraToUpdate.name);
          }
        }
      }
    },
    accessibleShow: function accessibleShow($elements) {
      var isFocusable = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
      var extraToUpdate = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : false;
      $elements.show();
      $elements.prop('aria-hidden', false);
      $elements.removeClass('sui-hidden');
      $elements.prop('hidden', false);

      if (isFocusable) {
        $elements.attr('tabindex', '0');
      }

      if (extraToUpdate) {
        if ('undefined' !== typeof extraToUpdate.name) {
          if ('undefined' !== typeof extraToUpdate.value) {
            $elements.attr(extraToUpdate.name, extraToUpdate.value);
          } else {
            $elements.removeAttr(extraToUpdate.name);
          }
        }
      }
    },
    showHideDependencyOnSelectChange: function showHideDependencyOnSelectChange($parent) {
      var $selectsWithContainers = $parent ? $parent.find('select.hustle-select-with-container') : $('select.hustle-select-with-container');
      $selectsWithContainers.each(function () {
        var $this = $(this),
            $depContainer = $("[data-field-content=\"".concat(this.name, "\"]")),
            valuesOn = $this.data('content-on') ? $this.data('content-on').split(',') : false,
            valuesOff = $this.data('content-off') ? $this.data('content-off').split(',') : false;

        var doToggle = function doToggle() {
          var currentVal = $this.val(),
              doShow = valuesOn ? valuesOn.includes(currentVal) : !valuesOff.includes(currentVal);

          if (doShow) {
            Module.Utils.accessibleShow($depContainer);
          } else {
            Module.Utils.accessibleHide($depContainer);
          }
        }; // Do it on load.


        doToggle(); // And do it on change.

        $this.on('change', function () {
          return doToggle();
        });
      });
    },
    serializeObject: function serializeObject($form) {
      var object = {},
          array = $form.serializeArray();
      $.each(array, function () {
        if (undefined !== object[this.name]) {
          if (!object[this.name].push) {
            object[this.name] = [object[this.name]];
          }

          object[this.name].push(this.value || '');
        } else {
          object[this.name] = this.value || '';
        }
      });
      $form.find('input:disabled[name]').each(function () {
        object[this.name] = this.value || '';
      });
      $form.find('select:disabled[name]').each(function () {
        object[this.name] = this.value || '';
      });
      $form.find('input[type="checkbox"]:not(:checked)').each(function () {
        if (undefined === object[this.name]) {
          object[this.name] = '0';
        } else if ('0' === object[this.name] && !$form.find("input[name=\"".concat(this.name, "\"]:checked")).length) {
          object[this.name] = [];
        } else if (!Array.isArray(object[this.name])) {
          object[this.name] = [object[this.name]];
        }
      });
      return object;
    }
  };
  /**
   * One callback to rule them all.
   * Receives the events from single module actions.
   * Call another callback or does an action (eg. a redirect) according to the ajax request response.
   * Used in module listing pages and dashboard.
   *
   * @since 4.0.3
   */

  Module.handleActions = {
    context: '',
    $target: null,

    /**
     * @param {Object} data AJAX request response.
     */
    responseData: {},

    /**
     * Function to initiate the action.
     *
     * @since 4.0.3
     * @param {Object} e
     * @param {string} context Where it's called from. dashboard|listing
     */
    initAction: function initAction(e, context) {
      var _this = this;

      e.preventDefault();
      this.context = context;
      this.$target = $(e.currentTarget);
      var self = this,
          relatedFormId = this.$target.data('form-id'),
          actionData = this.$target.data();
      var data = new FormData(); // Grab the form's data if the action has a related form.

      if ('undefined' !== typeof relatedFormId) {
        var $form = $('#' + relatedFormId);

        if ($form.length) {
          data = new FormData($form[0]);
        }
      }

      $.each(actionData, function (name, value) {
        return data.append(name, value);
      });
      data.append('context', this.context);
      data.append('_ajax_nonce', optinVars.single_module_action_nonce);
      data.append('action', 'hustle_module_handle_single_action');
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data,
        contentType: false,
        processData: false
      }).done(function (res) {
        // If there's a defined callback, call it.
        if (res.data.callback && 'function' === typeof self[res.data.callback]) {
          _this.responseData = res.data; // This calls the "action{ hustle action }" function from this view.
          // For example: actionToggleStatus();

          self[res.data.callback]();
        } else if (res.data.url) {
          window.location.assign(res.data.url);
        } else if (res.data.notification) {
          Module.Notification.open(res.data.notification.status, res.data.notification.message, res.data.notification.delay);
        } else if (!res.success) {
          Module.Notification.open('error', optinVars.messages.something_went_wrong, false);
        } // Don't remove the 'loading' icon when redirecting/reloading.


        if (!res.data.url) {
          $('.sui-button-onload').removeClass('sui-button-onload');
        }
      }).fail(function () {
        $('.sui-button-onload').removeClass('sui-button-onload');
      });
    },

    /**
     * initAction succcess callback for "toggle-tracking".
     * Only for Listing.
     *
     * @since 4.0.3
     */
    actionToggleTracking: function actionToggleTracking() {
      var $accordionContainer, isTrackingEnabled;

      if (!this.responseData.is_embed_or_sshare) {
        isTrackingEnabled = 1 - (this.responseData.was_enabled ? 1 : 0);
        $accordionContainer = this.$target.parents('.sui-accordion-item');
        this.$target.data('enabled', isTrackingEnabled);
        this.$target.find('.hustle-toggle-tracking-button-description').toggleClass('sui-hidden');
      } else {
        var $button = $('.hustle-manage-tracking-button[data-module-id="' + this.$target.data('module-id') + '"]');
        $button.data('tracking-types', this.responseData.enabled_types);
        isTrackingEnabled = 0 !== this.responseData.enabled_types.length;
        $accordionContainer = $button.parents('.sui-accordion-item');
        SUI.closeModal();
      } // Update the tracking chart if it was being displayed.


      if ($accordionContainer.hasClass('sui-accordion-item--open')) {
        $accordionContainer.find('.sui-accordion-open-indicator').trigger('click').trigger('click');
      } // Display the 'Analytics Disable' tag if the module is active and tracking is disabled.


      var displayTag = this.responseData.is_active && !isTrackingEnabled;
      this.toggleTrackingDisabledTag(displayTag, $accordionContainer);
      Module.Notification.open('success', this.responseData.message, 10000);
    },
    actionToggleStatus: function actionToggleStatus() {
      if ('listing' === this.context) {
        this.listingToggleStatus();
      } else {
        this.dashboardToggleStatus();
      }
    },

    /**
     * initAction succcess callback for "toggle-status".
     *
     * @since 4.0.4
     */
    listingToggleStatus: function listingToggleStatus() {
      var $accordionContainer = this.$target.closest('.sui-accordion-item'),
          $accordionTag = $accordionContainer.find('.sui-accordion-item-title span.sui-tag');
      $accordionTag.toggleClass('sui-tag-blue');
      $accordionTag.find('.hustle-toggle-status-button-description').toggleClass('sui-hidden');
      this.$target.find('.hustle-toggle-status-button-description').toggleClass('sui-hidden'); // Update tracking data

      if ($accordionContainer.hasClass('sui-accordion-item--open')) {
        $accordionContainer.find('.sui-accordion-open-indicator').trigger('click').trigger('click');
      } // Display the 'Analytics Disable' tag if the module is active and tracking is disabled.


      var displayTag = this.responseData.is_active && !this.responseData.is_tracking_enabled;
      this.toggleTrackingDisabledTag(displayTag, $accordionContainer);
    },

    /**
     * initAction succcess callback for "toggle-status".
     *
     * @since 4.0.4
     */
    dashboardToggleStatus: function dashboardToggleStatus() {
      var isActive = this.responseData.is_active;
      this.$target.find('.hustle-toggle-status-button-description').toggleClass('sui-hidden');
      var tooltip = this.$target.parents('td.hui-status').find('span.sui-tooltip');
      tooltip.removeClass('sui-draft sui-published');

      if (isActive) {
        tooltip.addClass('sui-published').attr('data-tooltip', optinVars.messages.commons.published);
      } else {
        tooltip.addClass('sui-draft').attr('data-tooltip', optinVars.messages.commons.draft);
      }
    },
    actionImportDisplayError: function actionImportDisplayError() {
      var message = this.responseData.message,
          $dialog = this.$target.closest('.sui-modal'),
          dialogId = $dialog.find('.sui-modal-content').attr('id'),
          noticeId = dialogId + '-error-notice';
      Module.Notification.open('error', message, false, noticeId, false);
      $dialog.find('input[name="import_file"]').focus();
    },
    toggleTrackingDisabledTag: function toggleTrackingDisabledTag(isDisplay, $accordionContainer) {
      var $trackingDisabledTag = $accordionContainer.find('.hustle-analytics-disabled-tag');

      if (isDisplay) {
        $trackingDisabledTag.removeClass('sui-hidden');
      } else {
        $trackingDisabledTag.addClass('sui-hidden');
      }
    }
  };
  var Optin = window.Optin || {};

  Optin.globalMixin = function () {
    _.mixin({
      /**
       * Converts val to boolian
       *
       * @param {*} val Value to check.
       * @return {boolean} Passed value as boolean.
       */
      toBool: function toBool(val) {
        if (_.isBoolean(val)) {
          return val;
        }

        if (_.isString(val) && -1 !== ['true', 'false', '1'].indexOf(val.toLowerCase())) {
          return 'true' === val.toLowerCase() || '1' === val.toLowerCase() ? true : false;
        }

        if (_.isNumber(val)) {
          return !!val;
        }

        if (_.isUndefined(val) || _.isNull(val) || _.isNaN(val)) {
          return false;
        }

        return val;
      },

      /**
       * Checks if val is truthy
       *
       * @param {*} val Value to check.
       * @return {boolean} Passed value as boolean.
       */
      isTrue: function isTrue(val) {
        if (_.isUndefined(val) || _.isNull(val) || _.isNaN(val)) {
          return false;
        }

        if (_.isNumber(val)) {
          return 0 !== val;
        }

        val = val.toString().toLowerCase();
        return -1 !== ['1', 'true', 'on'].indexOf(val);
      },
      isFalse: function isFalse(val) {
        return !_.isTrue(val);
      },
      controlBase: function controlBase(checked, current, attribute) {
        attribute = _.isUndefined(attribute) ? 'checked' : attribute;
        checked = _.toBool(checked);
        current = _.isBoolean(checked) ? _.isTrue(current) : current;

        if (_.isEqual(checked, current)) {
          return attribute + '=' + attribute;
        }

        return '';
      },

      /**
       * Checks whether the input should be checked.
       *
       * @param {number|string} checked Currently checked value.
       * @param {number|string} current Current value in the iteration.
       * @return {string} Returns checked="checked" if checked variable is equal to current state.
       */
      checked: function checked(_checked, current) {
        return _.controlBase(_checked, current, 'checked');
      },

      /**
       * Checks whether the option should be selected.
       *
       * @param {number|string} selected Currently checked value.
       * @param {number|string} current Current value in the iteration.
       * @return {string} Returns selected="selected" if checked variable is equal to current state.
       */
      selected: function selected(_selected, current) {
        return _.controlBase(_selected, current, 'selected');
      },

      /**
       * Checks whether the thing should be disabled.
       *
       * @param {number|string} disabled Currently checked value.
       * @param {number|string} current Current value in the iteration.
       * @return {string} Returns disabled="disabled" if checked variable is equal to current state.
       */
      disabled: function disabled(_disabled, current) {
        return _.controlBase(_disabled, current, 'disabled');
      },

      /**
       * Returns css class based on the passed condition.
       *
       * @param {*} conditon The condition to check.
       * @param {string} className Class to add if the condition is true.
       * @param {string} negatingClass Class to add if the condition is not true.
       * @return {string} Class to add.
       */
      class: function _class(conditon, className, negatingClass) {
        if (_.isTrue(conditon)) {
          return className;
        }

        return 'undefined' !== typeof negatingClass ? negatingClass : '';
      }
    });
  };

  Optin.globalMixin();
  /**
   * Recursive toJSON
   *
   * @return {*} JSON.
   */

  Backbone.Model.prototype.toJSON = function () {
    var json = _.clone(this.attributes);

    var attr;

    for (attr in json) {
      if (json[attr] instanceof Backbone.Model || Backbone.Collection && json[attr] instanceof Backbone.Collection) {
        json[attr] = json[attr].toJSON();
      }
    }

    return json;
  };
})(jQuery);
function _createForOfIteratorHelper(o, allowArrayLike) { var it; if (typeof Symbol === "undefined" || o[Symbol.iterator] == null) { if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || allowArrayLike && o && typeof o.length === "number") { if (it) o = it; var i = 0; var F = function F() {}; return { s: F, n: function n() { if (i >= o.length) return { done: true }; return { done: false, value: o[i++] }; }, e: function e(_e) { throw _e; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var normalCompletion = true, didErr = false, err; return { s: function s() { it = o[Symbol.iterator](); }, n: function n() { var step = it.next(); normalCompletion = step.done; return step; }, e: function e(_e2) { didErr = true; err = _e2; }, f: function f() { try { if (!normalCompletion && it.return != null) it.return(); } finally { if (didErr) throw err; } } }; }

function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }

function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) { arr2[i] = arr[i]; } return arr2; }

Hustle.define('SShare.Content_View', function ($) {
  'use strict';

  return Hustle.View.extend(_.extend({}, Hustle.get('Mixins.Module_Content'), {
    el: '#hustle-wizard-content',
    activePlatforms: [],
    events: {
      'change select.hustle-select-field-variables': 'addPlaceholderToField',
      'click ul.wpmudev-tabs-menu li label': 'toggleCheckbox',
      // Open Add Platforms popup
      'click .hustle-choose-platforms': 'openPlatformsModal'
    },
    render: function render() {
      var me = this,
          data = this.model.toJSON();

      if ('undefined' !== typeof data.social_icons && data.social_icons) {
        for (var platform in data.social_icons) {
          me.addPlatformToPanel(platform, data.social_icons[platform]);
        }
      } // Initiate the sortable functionality to sort form platforms' order.


      var sortableContainer = this.$('#hustle-social-services').sortable({
        axis: 'y',
        containment: '.sui-box-builder'
      });
      sortableContainer.on('sortupdate', $.proxy(me.platformsOrderChanged, me, sortableContainer)); //add all platforms to Add Platforms popup

      for (var _platform in optinVars.social_platforms) {
        me.addPlatformToDialog(_platform);
      }

      this.bindRemoveService();

      if ('true' === Module.Utils.getUrlParam('new')) {
        Module.Notification.open('success', optinVars.messages.module_created, 10000);
      }
    },
    bindRemoveService: function bindRemoveService() {
      // Delete Social Service
      $('#hustle-wizard-content .hustle-remove-social-service').off('click').on('click', $.proxy(this.removeService, this));
    },
    openPlatformsModal: function openPlatformsModal() {
      var self = this,
          savedPlatforms = this.model.get('social_icons'),
          platforms = 'undefined' !== typeof savedPlatforms ? Object.keys(savedPlatforms) : [],
          PlatformsModalView = Hustle.get('Modals.Services_Platforms'),
          platformsModal = new PlatformsModalView(platforms);
      platformsModal.on('platforms:added', $.proxy(self.addNewPlatforms, self)); // Show dialog

      SUI.openModal('hustle-dialog--add-platforms', this.$('.hustle-choose-platforms')[0], this.$('#hustle-dialog--add-platforms .hustle-modal-close')[0], true);
    },
    addNewPlatforms: function addNewPlatforms(platforms) {
      var _this = this;

      if (!this.model.get('social_icons')) {
        this.model.set('social_icons', {});
      }

      var self = this,
          savedPlatforms = _.extend({}, this.model.get('social_icons'));

      $.each(platforms, function (i, platform) {
        if (savedPlatforms && platform in savedPlatforms) {
          //If this platform is already set, abort. Prevent duplicated platforms.
          return true;
        }

        self.addPlatformToPanel(platform, {});

        var data = _this.getPlatformDefaults(platform);

        savedPlatforms[platform] = data;
      });
      this.bindRemoveService();
      this.model.set('social_icons', savedPlatforms);
      Hustle.Events.trigger('view.rendered', this);
    },
    addPlatformToPanel: function addPlatformToPanel(platform, data) {
      var template = Optin.template('hustle-platform-row-tpl'),
          $platformsContainer = this.$('#hustle-social-services');
      data = _.extend({}, this.getPlatformViewDefaults(platform), data);
      this.activePlatforms.push(platform);
      $platformsContainer.append(template(data));
    },
    addPlatformToDialog: function addPlatformToDialog(platform) {
      var template = Optin.template('hustle-add-platform-li-tpl'),
          $container = $('#hustle_add_platforms_container'),
          data = this.getPlatformViewDefaults(platform);
      $container.append(template(data));
    },
    getPlatformDefaults: function getPlatformDefaults(platform) {
      var label = platform in optinVars.social_platforms ? optinVars.social_platforms[platform] : platform,
          defaults = {
        platform: platform,
        label: label,
        type: 'click',
        counter: '0',
        link: ''
      };

      if ('email' === platform) {
        defaults.title = '{post_title}';
        defaults.message = optinVars.social_platforms_data.email_message_default;
      }

      return defaults;
    },
    getPlatformViewDefaults: function getPlatformViewDefaults(platform) {
      var data = this.model.toJSON(),
          counterEnabled = 'undefined' === typeof data.counter_enabled ? 'true' : data.counter_enabled,
          changedStyles = {
        fivehundredpx: '500px'
      },
          hasEndpoint = -1 !== optinVars.social_platforms_with_endpoints.indexOf(platform),
          hasCounter = -1 !== optinVars.social_platforms_with_api.indexOf(platform);

      var platformStyle = platform in changedStyles ? changedStyles[platform] : platform,
          viewDefaults = _.extend({}, this.getPlatformDefaults(platform), {
        platform_style: platformStyle,
        counter_enabled: counterEnabled,
        hasEndpoint: hasEndpoint,
        hasCounter: hasCounter
      });

      return viewDefaults;
    },

    /**
     * Assign the new platfom order to the model. Triggered when the platforms are sorted.
     *
     * @since 4.0.0
     * @param {Object} sortable
     */
    platformsOrderChanged: function platformsOrderChanged(sortable) {
      var platforms = this.model.get('social_icons'),
          newOrder = sortable.sortable('toArray', {
        attribute: 'data-platform'
      }),
          orderedPlatforms = {};

      var _iterator = _createForOfIteratorHelper(newOrder),
          _step;

      try {
        for (_iterator.s(); !(_step = _iterator.n()).done;) {
          var id = _step.value;
          orderedPlatforms[id] = platforms[id];
        }
      } catch (err) {
        _iterator.e(err);
      } finally {
        _iterator.f();
      }

      this.model.set('social_icons', orderedPlatforms);
      this.model.trigger('change', this.model);
    },
    removeService: function removeService(e) {
      var $this = $(e.currentTarget),
          platform = $this.data('platform'),
          socialIcons = this.model.get('social_icons'),
          $platformContainer = this.$('#hustle-platform-' + platform); // Remove the platform container from the page.

      $platformContainer.remove();
      this.activePlatforms = _.without(this.activePlatforms, platform);
      delete socialIcons[platform];
      this.model.trigger('change', this.model);
      e.stopPropagation();
    },
    modelUpdated: function modelUpdated(e) {
      var changed = e.changed,
          key = 'undefined' !== typeof Object.keys(changed)[0] ? Object.keys(changed)[0] : '';
      var socialIcons; // for service_type

      if ('service_type' in changed) {
        this.serviceTypeUpdated(changed.service_type);
      } // for click_counter


      if ('click_counter' in changed) {
        this.clickCounterUpdated(changed.click_counter);
      } else if (-1 !== key.indexOf('_counter')) {
        var platform = key.slice(0, -8);
        socialIcons = this.model.get('social_icons');

        if (platform in socialIcons) {
          socialIcons[platform].counter = parseInt(changed[key]);
        }

        this.model.unset(key, {
          silent: true
        });
      }

      if (-1 !== key.indexOf('_link')) {
        var _platform2 = key.slice(0, -5);

        socialIcons = this.model.get('social_icons');

        if (_platform2 in socialIcons) {
          socialIcons[_platform2].link = changed[key];
        }

        this.model.unset(key, {
          silent: true
        });
      }

      if (-1 !== key.indexOf('_type')) {
        var _platform3 = key.slice(0, -5);

        socialIcons = this.model.get('social_icons');

        if (_platform3 in socialIcons) {
          socialIcons[_platform3].type = 'native' === changed[key] ? 'native' : 'click';
        }

        this.model.unset(key, {
          silent: true
        });
      }

      if ('email_title' in changed) {
        var _platform4 = 'email';
        socialIcons = this.model.get('social_icons');

        if (_platform4 in socialIcons) {
          socialIcons[_platform4].title = changed[key];
        }

        this.model.unset(key, {
          silent: true
        });
      }

      if ('email_message' in changed) {
        var _platform5 = 'email';
        socialIcons = this.model.get('social_icons');

        if (_platform5 in socialIcons) {
          socialIcons[_platform5].message = changed[key];
        }

        this.model.unset(key, {
          silent: true
        });
      }
    },
    serviceTypeUpdated: function serviceTypeUpdated(val) {
      var $counterOptions = this.$('#wpmudev-sshare-counter-options'),
          $nativeOptions = $('.wph-wizard-services-icons-native'),
          $customOptions = $('.wph-wizard-services-icons-custom');

      if ('native' === val) {
        $counterOptions.removeClass('wpmudev-hidden');
        $customOptions.addClass('wpmudev-hidden');
        $nativeOptions.removeClass('wpmudev-hidden');
      } else {
        $counterOptions.addClass('wpmudev-hidden');
        $nativeOptions.addClass('wpmudev-hidden');
        $customOptions.removeClass('wpmudev-hidden');
      }
    },
    clickCounterUpdated: function clickCounterUpdated(val) {
      var $counterNotice = $('#wpmudev-sshare-counter-options .hustle-twitter-notice');

      if ('native' === val) {
        $counterNotice.removeClass('wpmudev-hidden');
      } else if (!$counterNotice.hasClass('wpmudev-hidden')) {
        $counterNotice.addClass('wpmudev-hidden');
      }

      $('#wph-wizard-services-icons-native .wpmudev-social-item').each(function () {
        var $checkbox = $(this).find('.toggle-checkbox'),
            isChecked = $checkbox.is(':checked'),
            $inputCounter = $(this).find('input.wpmudev-input_number');

        if ('none' !== val && isChecked) {
          $inputCounter.removeClass('wpmudev-hidden');
        } else if (!$inputCounter.hasClass('wpmudev-hidden')) {
          $inputCounter.addClass('wpmudev-hidden');
        }
      });
      $('#wph-wizard-services-icons-native #wpmudev-counter-title>strong').removeClass('wpmudev-hidden');

      if ('none' === val) {
        $('#wph-wizard-services-icons-native #wpmudev-counter-title>strong:first-child').addClass('wpmudev-hidden');
      } else {
        $('#wph-wizard-services-icons-native #wpmudev-counter-title>strong:nth-child(2)').addClass('wpmudev-hidden');
      }
    },
    toggleCheckbox: function toggleCheckbox(e) {
      e.preventDefault();
      e.stopPropagation();
      var $this = this.$(e.target),
          $li = $this.closest('li');

      if ($li.hasClass('current')) {
        return;
      }

      $li.addClass('current');
      $li.siblings().removeClass('current');
      var $input = $li.find('input'),
          prop = $input.data('attribute');
      this.model.set(prop, $input.val());
    },
    setSocialIcons: function setSocialIcons() {
      var services = this.model.toJSON();
      services = this.getSocialIconsData(services);
      this.model.set('social_icons', services.social_icons, {
        silent: true
      });
    },
    getSocialIconsData: function getSocialIconsData(services) {
      var $socialContainers = $('#wph-wizard-services-icons-' + services.service_type + ' .wpmudev-social-item'),
          socialIcons = {};
      $socialContainers.each(function () {
        var $sc = $(this),
            $toggleInput = $sc.find('input.toggle-checkbox'),
            icon = $toggleInput.data('id'),
            $counter = $sc.find('input.wpmudev-input_number'),
            $link = $sc.find('input.wpmudev-input_text'); // check if counter have negative values

        if ($counter.length) {
          var counterVal = parseInt($counter.val());

          if (0 > counterVal) {
            $counter.val(0);
          }
        }

        if ($toggleInput.is(':checked')) {
          socialIcons[icon] = {
            enabled: true,
            counter: $counter.length ? $counter.val() : '0',
            link: $link.length ? $link.val() : ''
          };
        }
      });

      if ($socialContainers.length) {
        services.social_icons = socialIcons;
      }

      return services;
    },
    addPlaceholderToField: function addPlaceholderToField(e) {
      var $select = $(e.currentTarget),
          selectedPlaceholder = $select.val(),
          targetInputName = $select.data('field'),
          $input = $("[name=\"".concat(targetInputName, "\"]")),
          val = $input.val() + selectedPlaceholder;
      $input.val(val).trigger('change');
    }
  }));
});
Hustle.define('SShare.Design_View', function ($) {
  'use strict';

  return Hustle.View.extend(_.extend({}, Hustle.get('Mixins.Model_Updater'), Hustle.get('Mixins.Module_Design'), {
    beforeRender: function beforeRender() {
      this.listenTo(this.model, 'change', this.modelUpdated); // Update the Appearance tab view when the display types are changed in the Display tab.

      Hustle.Events.off('modules.view.displayTypeUpdated').on('modules.view.displayTypeUpdated', $.proxy(this.viewChangedDisplayTab, this));
    },
    render: function render() {
      var _this = this;

      this.createPickers($('.sui-colorpicker-input')); // Trigger preview when this tab is shown.

      $('a[data-tab="appearance"]').on('click', $.proxy(this.updatePreview, this));
      $('.sui-box[data-tab="display"] .sui-button[data-direction="next"').on('click', $.proxy(this.updatePreview, this));
      $('.sui-box[data-tab="visibility"] .sui-button[data-direction="prev"').on('click', $.proxy(this.updatePreview, this));
      this.updateSocialIconsPickers();
      setTimeout(function () {
        return _this.updatePreview();
      }, 100);
    },
    updatePreview: function updatePreview() {
      $('#hui-preview-social-shares-floating').trigger('hustle_update_prewiev');
    },
    // Adjust the view when model is updated
    modelUpdated: function modelUpdated(model) {
      var changedKey = Object.keys(model.changed)[0],
          actionToDo = this.getActionOnContentModelUpdated(changedKey);

      if ('undefined' !== typeof actionToDo) {
        actionToDo();
      }

      this.updatePreview();
    },
    getActionOnContentModelUpdated: function getActionOnContentModelUpdated(changedKey) {
      var _this2 = this;

      var functions = {
        icon_style: function icon_style() {
          return _this2.updateSocialIconsPickers();
        }
      };
      return functions[changedKey];
    },
    updateSocialIconsPickers: function updateSocialIconsPickers() {
      var iconStyle = this.model.get('icon_style');

      if ('flat' === iconStyle) {
        $('#hustle-floating-icons-custom-background').addClass('sui-hidden');
        $('#hustle-widget-icons-custom-background').addClass('sui-hidden');
      } else {
        $('#hustle-floating-icons-custom-background').removeClass('sui-hidden');
        $('#hustle-widget-icons-custom-background').removeClass('sui-hidden');
      }

      if ('outline' === iconStyle) {
        // Replace "icon background" text with "icon border"
        this.$('.hustle-icon-bg-color-label').addClass('sui-hidden');
        this.$('.hustle-icon-border-color-label').removeClass('sui-hidden'); // Hide counter border color

        $('#hustle-floating-counter-border').addClass('sui-hidden');
        $('#hustle-widget-counter-border').addClass('sui-hidden');
      } else {
        // Replace "icon border" text with "icon background"
        this.$('.hustle-icon-bg-color-label').removeClass('sui-hidden');
        this.$('.hustle-icon-border-color-label').addClass('sui-hidden'); // Show counter border color

        $('#hustle-floating-counter-border').removeClass('sui-hidden');
        $('#hustle-widget-counter-border').removeClass('sui-hidden');
      }
    },
    viewChangedDisplayTab: function viewChangedDisplayTab(model) {
      var inline = model.get('inline_enabled'),
          widget = model.get('widget_enabled'),
          shortcode = model.get('shortcode_enabled'),
          floatDesktop = model.get('float_desktop_enabled'),
          floatMobile = model.get('float_mobile_enabled'),
          isWidgetEnabled = _.intersection([1, '1', 'true'], [inline, widget, shortcode]).length,
          isFloatingEnabled = _.intersection([1, '1', 'true'], [floatMobile, floatDesktop]).length; // TODO: we should be using this.$( '...' ) here instead.


      if (isFloatingEnabled) {
        $('#hustle-appearance-floating-icons-row').show();
        $('#hustle-appearance-floating-icons-placeholder').hide();
      } else {
        $('#hustle-appearance-floating-icons-row').hide();
        $('#hustle-appearance-floating-icons-placeholder').show();
      }

      if (isWidgetEnabled) {
        $('#hustle-appearance-widget-icons-row').show();
        $('#hustle-appearance-widget-icons-placeholder').hide();
      } else {
        $('#hustle-appearance-widget-icons-row').hide();
        $('#hustle-appearance-widget-icons-placeholder').show();
      }

      if (!isWidgetEnabled && !isFloatingEnabled) {
        $('#hustle-appearance-icons-style').hide();
        $('#hustle-appearance-empty-message').show();
        $('#hustle-appearance-floating-icons-placeholder').hide();
        $('#hustle-appearance-widget-icons-placeholder').hide();
      } else {
        $('#hustle-appearance-icons-style').show();
        $('#hustle-appearance-empty-message').hide();
      }
    },
    colorPickerCleared: function colorPickerCleared(e, parentSuiPickerInput) {
      var inputName = parentSuiPickerInput.data('attribute'),
          resetValue = optinVars.palettes.sshare_defaults[inputName],
          $suiPicker = parentSuiPickerInput.closest('.sui-colorpicker-wrap'),
          $suiPickerValue = $suiPicker.find('.sui-colorpicker-value'),
          $suiPickerColor = $suiPicker.find('.sui-colorpicker-value span[role=button]'),
          $wpPicker = parentSuiPickerInput.closest('.wp-picker-container'),
          $wpPickerClear = $wpPicker.find('.wp-picker-clear');
      $wpPickerClear.click();
      $suiPickerValue.find('input').val(resetValue);
      parentSuiPickerInput.val(resetValue).trigger('change');
      $suiPickerColor.find('span').css({
        'background-color': resetValue
      });
      e.preventDefault();
      e.stopPropagation();
    },
    updatePickers: function updatePickers() {
      var self = this;

      if ('undefined' !== typeof optinVars.palettes.sshare_defaults) {
        var colors = optinVars.palettes.sshare_defaults; // update color palettes

        _.each(colors, function (color, key) {
          self.$('input[data-attribute="' + key + '"]').val(color).trigger('change');
        });
      }
    }
  }));
});
Hustle.define('SShare.Display_View', function () {
  'use strict';

  return Hustle.View.extend(_.extend({}, Hustle.get('Mixins.Module_Display'), {
    viewChanged: function viewChanged(changed) {
      if (_.intersection(['float_desktop_enabled', 'float_mobile_enabled', 'inline_enabled', 'widget_enabled', 'shortcode_enabled'], Object.keys(changed)).length) {
        // Show/hide some settings in the Appearance tab.
        Hustle.Events.trigger('modules.view.displayTypeUpdated', this.model);
      } else if ('float_desktop_position' in changed) {
        if ('right' === changed.float_desktop_position) {
          this.$('#hustle-float_desktop-left-offset-label').addClass('sui-hidden');
          this.$('#hustle-float_desktop-right-offset-label').removeClass('sui-hidden');
          this.$('#hustle-float_desktop-offset-x-wrapper').removeClass('sui-hidden');
        } else if ('left' === changed.float_desktop_position) {
          this.$('#hustle-float_desktop-left-offset-label').removeClass('sui-hidden');
          this.$('#hustle-float_desktop-right-offset-label').addClass('sui-hidden');
          this.$('#hustle-float_desktop-offset-x-wrapper').removeClass('sui-hidden');
        } else {
          this.$('#hustle-float_desktop-offset-x-wrapper').addClass('sui-hidden');
        }
      } else if ('float_desktop_position_y' in changed) {
        if ('bottom' === changed.float_desktop_position_y) {
          this.$('#hustle-float_desktop-top-offset-label').addClass('sui-hidden');
          this.$('#hustle-float_desktop-bottom-offset-label').removeClass('sui-hidden');
        } else {
          this.$('#hustle-float_desktop-top-offset-label').removeClass('sui-hidden');
          this.$('#hustle-float_desktop-bottom-offset-label').addClass('sui-hidden');
        }
      } else if ('float_mobile_position' in changed) {
        if ('right' === changed.float_mobile_position) {
          this.$('#hustle-float_mobile-left-offset-label').addClass('sui-hidden');
          this.$('#hustle-float_mobile-right-offset-label').removeClass('sui-hidden');
          this.$('#hustle-float_mobile-offset-x-wrapper').removeClass('sui-hidden');
        } else if ('left' === changed.float_mobile_position) {
          this.$('#hustle-float_mobile-left-offset-label').removeClass('sui-hidden');
          this.$('#hustle-float_mobile-right-offset-label').addClass('sui-hidden');
          this.$('#hustle-float_mobile-offset-x-wrapper').removeClass('sui-hidden');
        } else {
          this.$('#hustle-float_mobile-offset-x-wrapper').addClass('sui-hidden');
        }
      } else if ('float_mobile_position_y' in changed) {
        if ('bottom' === changed.float_mobile_position_y) {
          this.$('#hustle-float_mobile-top-offset-label').addClass('sui-hidden');
          this.$('#hustle-float_mobile-bottom-offset-label').removeClass('sui-hidden');
        } else {
          this.$('#hustle-float_mobile-top-offset-label').removeClass('sui-hidden');
          this.$('#hustle-float_mobile-bottom-offset-label').addClass('sui-hidden');
        }
      }
    }
  }));
});
function _createForOfIteratorHelper(o, allowArrayLike) { var it; if (typeof Symbol === "undefined" || o[Symbol.iterator] == null) { if (Array.isArray(o) || (it = _unsupportedIterableToArray(o)) || allowArrayLike && o && typeof o.length === "number") { if (it) o = it; var i = 0; var F = function F() {}; return { s: F, n: function n() { if (i >= o.length) return { done: true }; return { done: false, value: o[i++] }; }, e: function e(_e) { throw _e; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var normalCompletion = true, didErr = false, err; return { s: function s() { it = o[Symbol.iterator](); }, n: function n() { var step = it.next(); normalCompletion = step.done; return step; }, e: function e(_e2) { didErr = true; err = _e2; }, f: function f() { try { if (!normalCompletion && it.return != null) it.return(); } finally { if (didErr) throw err; } } }; }

function _unsupportedIterableToArray(o, minLen) { if (!o) return; if (typeof o === "string") return _arrayLikeToArray(o, minLen); var n = Object.prototype.toString.call(o).slice(8, -1); if (n === "Object" && o.constructor) n = o.constructor.name; if (n === "Map" || n === "Set") return Array.from(o); if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return _arrayLikeToArray(o, minLen); }

function _arrayLikeToArray(arr, len) { if (len == null || len > arr.length) len = arr.length; for (var i = 0, arr2 = new Array(len); i < len; i++) { arr2[i] = arr[i]; } return arr2; }

Hustle.define('Modals.Services_Platforms', function () {
  'use strict';

  return Backbone.View.extend({
    el: '#hustle-dialog--add-platforms',
    selectedPlatforms: [],
    events: {
      'click .sui-box-selector input': 'selectPlatforms',
      //Add platforms
      'click #hustle-add-platforms': 'addPlatforms'
    },
    initialize: function initialize(platforms) {
      this.selectedPlatforms = platforms;
      this.$('.hustle-add-platforms-option').prop('checked', false).prop('disabled', false);

      var _iterator = _createForOfIteratorHelper(this.selectedPlatforms),
          _step;

      try {
        for (_iterator.s(); !(_step = _iterator.n()).done;) {
          var platform = _step.value;
          this.$('#hustle-social--' + platform).prop('checked', true).prop('disabled', true);
        }
      } catch (err) {
        _iterator.e(err);
      } finally {
        _iterator.f();
      }
    },
    selectPlatforms: function selectPlatforms(e) {
      var $input = this.$(e.target),
          $selectorLabel = this.$el.find('label[for="' + $input.attr('id') + '"]'),
          value = $input.val();
      $selectorLabel.toggleClass('selected');

      if ($input.prop('checked')) {
        this.selectedPlatforms.push(value);
      } else {
        this.selectedPlatforms = _.without(this.selectedPlatforms, value);
      }
    },
    checkPlatforms: function checkPlatforms() {
      var _iterator2 = _createForOfIteratorHelper(this.selectedPlatforms),
          _step2;

      try {
        for (_iterator2.s(); !(_step2 = _iterator2.n()).done;) {
          var platform = _step2.value;

          if (!this.$('#hustle-social--' + platform).prop('checked')) {
            this.selectedPlatforms = _.without(this.selectedPlatforms, platform);
          }
        }
      } catch (err) {
        _iterator2.e(err);
      } finally {
        _iterator2.f();
      }
    },
    addPlatforms: function addPlatforms(e) {
      var $button = this.$(e.target);
      $button.addClass('sui-button-onload');
      this.checkPlatforms();
      this.trigger('platforms:added', this.selectedPlatforms);
      setTimeout(function () {
        // Hide dialog
        SUI.closeModal();
        $button.removeClass('sui-button-onload');
      }, 500);
    }
  });
});
Hustle.define('SShare.View', function ($) {
  'use strict';

  return Hustle.View.extend(_.extend({}, Hustle.get('Mixins.Wizard_View'), {
    _events: {
      'hustle_update_prewiev #hui-preview-social-shares-floating': 'updatePreview'
    },
    updatePreview: function updatePreview() {
      var previewData = _.extend({}, this.model.toJSON(), this.getDataToSave());

      $.ajax({
        type: 'POST',
        url: ajaxurl,
        dataType: 'json',
        data: {
          action: 'hustle_preview_module',
          id: this.model.get('module_id'),
          previewData: previewData
        },
        success: function success(res) {
          if (res.success) {
            var $floatingContainer = $('#hui-preview-social-shares-floating'),
                $widgetContainer = $('#hui-preview-social-shares-widget');
            $floatingContainer.html(res.data.floatingHtml);
            $widgetContainer.html(res.data.widgetHtml);

            if (res.data.style) {
              $floatingContainer.append(res.data.style);
            }

            $('.hustle-share-icon').on('click', function (ev) {
              return ev.preventDefault();
            });
          }
        }
      });
    },

    /**
     * Overriding.
     *
     * @param {Object} opts
     */
    setTabsViews: function setTabsViews(opts) {
      this.contentView = opts.contentView;
      this.displayView = opts.displayView;
      this.designView = opts.designView;
      this.visibilityView = opts.visibilityView;
      this.moduleType = this.model.get('module_type');
    },

    /**
     * Overriding.
     */
    renderTabs: function renderTabs() {
      // Services
      this.contentView.delegateEvents(); // Appearance view

      this.designView.delegateEvents(); // Display Options View

      this.displayView.delegateEvents(); // Visibility view.

      this.visibilityView.delegateEvents();
      this.visibilityView.afterRender();
    },

    /**
     * Overriding.
     */
    sanitizeData: function sanitizeData() {},

    /**
     * Overriding.
     */
    getDataToSave: function getDataToSave() {
      return {
        content: this.contentView.model.toJSON(),
        display: this.displayView.model.toJSON(),
        design: this.designView.model.toJSON(),
        visibility: this.visibilityView.model.toJSON()
      };
    }
  }));
});
(function () {
  'use strict';
  /**
   * Listing Page
   */

  (function () {
    var page = '_page_hustle_popup_listing';

    if (page !== pagenow.substr(pagenow.length - page.length)) {
      return;
    }

    new Optin.listingBase({
      moduleType: optinVars.current.module_type
    });
  })();
  /**
   * Edit or New page
   */


  (function () {
    var page = '_page_hustle_popup';

    if (page !== pagenow.substr(pagenow.length - page.length)) {
      return;
    }

    var View = Hustle.View.extend(Hustle.get('Mixins.Wizard_View')),
        ViewContent = Hustle.View.extend(Hustle.get('Mixins.Module_Content')),
        ViewEmails = Hustle.View.extend(Hustle.get('Mixins.Module_Emails')),
        ViewDesign = Hustle.View.extend(Hustle.get('Mixins.Module_Design')),
        ViewVisibility = Hustle.View.extend(Hustle.get('Mixins.Module_Visibility')),
        ViewSettings = Hustle.View.extend(Hustle.get('Mixins.Module_Settings')),
        ViewIntegrations = Hustle.get('Module.IntegrationsView'),
        ModelView = Module.Model,
        BaseModel = Hustle.get('Models.M');
    return new View({
      model: new ModelView(optinVars.current.data || {}),
      contentView: new ViewContent({
        BaseModel: BaseModel
      }),
      emailsView: new ViewEmails({
        BaseModel: BaseModel
      }),
      designView: new ViewDesign({
        BaseModel: BaseModel
      }),
      integrationsView: new ViewIntegrations({
        BaseModel: BaseModel
      }),
      visibilityView: new ViewVisibility({
        BaseModel: BaseModel
      }),
      settingsView: new ViewSettings({
        BaseModel: BaseModel
      })
    });
  })();
})();
(function () {
  'use strict';
  /**
   * Listing Page
   */

  (function () {
    var page = '_page_hustle_slidein_listing';

    if (page !== pagenow.substr(pagenow.length - page.length)) {
      return;
    }

    new Optin.listingBase({
      moduleType: optinVars.current.module_type
    });
  })();
  /**
   * Edit or New page
   */


  (function () {
    var page = '_page_hustle_slidein';

    if (page !== pagenow.substr(pagenow.length - page.length)) {
      return;
    }

    var View = Hustle.View.extend(Hustle.get('Mixins.Wizard_View')),
        ViewContent = Hustle.View.extend(Hustle.get('Mixins.Module_Content')),
        ViewEmails = Hustle.View.extend(Hustle.get('Mixins.Module_Emails')),
        ViewDesign = Hustle.View.extend(Hustle.get('Mixins.Module_Design')),
        ViewVisibility = Hustle.View.extend(Hustle.get('Mixins.Module_Visibility')),
        ViewSettings = Hustle.View.extend(Hustle.get('Mixins.Module_Settings')),
        ViewIntegrations = Hustle.get('Module.IntegrationsView'),
        ModelView = Module.Model,
        BaseModel = Hustle.get('Models.M');
    return new View({
      model: new ModelView(optinVars.current.data || {}),
      contentView: new ViewContent({
        BaseModel: BaseModel
      }),
      emailsView: new ViewEmails({
        BaseModel: BaseModel
      }),
      designView: new ViewDesign({
        BaseModel: BaseModel
      }),
      integrationsView: new ViewIntegrations({
        BaseModel: BaseModel
      }),
      visibilityView: new ViewVisibility({
        BaseModel: BaseModel
      }),
      settingsView: new ViewSettings({
        BaseModel: BaseModel
      })
    });
  })();
})();
(function () {
  'use strict'; // Listings Page

  (function () {
    var page = '_page_hustle_embedded_listing';

    if (page !== pagenow.substr(pagenow.length - page.length)) {
      return;
    }

    new Optin.listingBase({
      moduleType: optinVars.current.module_type
    });
  })(); // Wizard Page


  (function () {
    var page = '_page_hustle_embedded';

    if (page !== pagenow.substr(pagenow.length - page.length)) {
      return;
    }

    var view = Hustle.View.extend(Hustle.get('Mixins.Wizard_View')),
        ViewContent = Hustle.View.extend(Hustle.get('Mixins.Module_Content')),
        ViewEmails = Hustle.View.extend(Hustle.get('Mixins.Module_Emails')),
        ViewDesign = Hustle.View.extend(Hustle.get('Mixins.Module_Design')),
        ViewDisplay = Hustle.View.extend(Hustle.get('Mixins.Module_Display')),
        ViewVisibility = Hustle.View.extend(Hustle.get('Mixins.Module_Visibility')),
        ViewSettings = Hustle.View.extend(Hustle.get('Mixins.Module_Settings')),
        ViewIntegrations = Hustle.get('Module.IntegrationsView'),
        viewModel = Module.Model,
        BaseModel = Hustle.get('Models.M');
    return new view({
      model: new viewModel(optinVars.current.data || {}),
      contentView: new ViewContent({
        BaseModel: BaseModel
      }),
      emailsView: new ViewEmails({
        BaseModel: BaseModel
      }),
      designView: new ViewDesign({
        BaseModel: BaseModel
      }),
      integrationsView: new ViewIntegrations({
        BaseModel: BaseModel
      }),
      displayView: new ViewDisplay({
        BaseModel: BaseModel
      }),
      visibilityView: new ViewVisibility({
        BaseModel: BaseModel
      }),
      settingsView: new ViewSettings({
        BaseModel: BaseModel
      })
    });
  })();
})();
(function () {
  'use strict';
  /**
   * Listing Page.
   */

  (function () {
    var page = '_page_hustle_sshare_listing';

    if (page !== pagenow.substr(pagenow.length - page.length)) {
      return;
    }

    new Optin.listingBase({
      moduleType: optinVars.current.module_type
    });
  })();
  /**
   * Wizard page.
   */


  (function () {
    var page = '_page_hustle_sshare';

    if (page !== pagenow.substr(pagenow.length - page.length)) {
      return;
    }

    var view = Hustle.get('SShare.View'),
        ViewContent = Hustle.get('SShare.Content_View'),
        ViewDisplay = Hustle.get('SShare.Display_View'),
        ViewDesign = Hustle.get('SShare.Design_View'),
        ViewVisibility = Hustle.View.extend(Hustle.get('Mixins.Module_Visibility')),
        viewModel = Module.Model,
        BaseModel = Hustle.get('Models.M');
    return new view({
      model: new viewModel(optinVars.current.data || {}),
      contentView: new ViewContent({
        BaseModel: BaseModel
      }),
      displayView: new ViewDisplay({
        BaseModel: BaseModel
      }),
      designView: new ViewDesign({
        BaseModel: BaseModel
      }),
      visibilityView: new ViewVisibility({
        BaseModel: BaseModel
      })
    });
  })();
})();
Hustle.define('Dashboard.View', function ($) {
  'use strict';

  if ('toplevel_page_hustle' !== pagenow) {
    // eslint-disable-line camelcase
    return;
  }

  var dashboardView = Backbone.View.extend({
    el: '.sui-wrap-hustle',
    events: {
      'click .hustle-preview-module-button': 'previewModule',
      'click .hustle-delete-module-button': 'openDeleteModal',
      'click .hustle-free-version-create': 'showUpgradeModal',
      'click .sui-dropdown .hustle-onload-icon-action': 'addLoadingIconToActionsButton',
      // Modules' actions.
      'click .hustle-single-module-button-action': 'handleSingleModuleAction'
    },
    initialize: function initialize() {
      if ($('#hustle-dialog--welcome').length) {
        this.openWelcomeDialog();
      } else if ($('#hustle-dialog--migrate').length) {
        this.openMigrateDialog();
      } else if ($('#hustle-dialog--release-highlight').length) {
        this.openReleaseHighlightDialog();
      }

      this.doActionsBasedOnUrl();
    },
    doActionsBasedOnUrl: function doActionsBasedOnUrl() {
      // Display notice based on URL parameters.
      if (Module.Utils.getUrlParam('show-notice')) {
        var status = 'success' === Module.Utils.getUrlParam('show-notice') ? 'success' : 'error',
            notice = Module.Utils.getUrlParam('notice'),
            message = notice && 'undefined' !== optinVars.messages[notice] ? optinVars.messages[notice] : Module.Utils.getUrlParam('notice-message');

        if ('undefined' !== typeof message && message.length) {
          Module.Notification.open(status, message);
        }
      }
    },
    previewModule: function previewModule(e) {
      e.preventDefault();
      var $button = $(e.currentTarget);
      this.getPreviewView().open($button.data('id'), $button.data('type'), $button, {
        module_name: $button.data('name')
      });
    },
    getPreviewView: function getPreviewView() {
      if (!this.previewView) {
        var previewView = Hustle.get('Modals.Preview');
        this.previewView = new previewView();
      }

      return this.previewView;
    },
    showUpgradeModal: function showUpgradeModal(e) {
      if ('undefined' !== typeof e) {
        e.preventDefault();
      }

      var $upgradeModal = $('#wph-upgrade-modal');
      $upgradeModal.addClass('wpmudev-modal-active');
    },

    /**
     * @since 4.0.0
     * @param {Object} e
     */
    openDeleteModal: function openDeleteModal(e) {
      e.preventDefault();
      var $this = $(e.currentTarget),
          data = {
        id: $this.data('id'),
        nonce: $this.data('nonce'),
        action: 'delete',
        title: $this.data('title'),
        description: $this.data('description')
      };
      Module.deleteModal.open(data, $this[0]);
    },
    addLoadingIconToActionsButton: function addLoadingIconToActionsButton(e) {
      var $actionButton = $(e.currentTarget),
          $mainButton = $actionButton.closest('.sui-dropdown').find('.sui-dropdown-anchor');
      $mainButton.addClass('sui-button-onload');
    },
    openWelcomeDialog: function openWelcomeDialog() {
      Hustle.get('Modals.Welcome');
    },
    openMigrateDialog: function openMigrateDialog() {
      Hustle.get('Modals.Migration');
    },
    openReleaseHighlightDialog: function openReleaseHighlightDialog() {
      Hustle.get('Modals.ReleaseHighlight');
    },
    handleSingleModuleAction: function handleSingleModuleAction(e) {
      Module.handleActions.initAction(e, 'dashboard', this);
    }
  });
  new dashboardView();
});
Hustle.define('Integrations.View', function ($) {
  'use strict';

  var page = '_page_hustle_integrations';

  if (page !== pagenow.substr(pagenow.length - page.length)) {
    return;
  }

  var integrationsView = Backbone.View.extend({
    el: '.sui-wrap-hustle',
    events: {
      'click .connect-integration': 'connectIntegration',
      'keypress .connect-integration': 'preventEnterKeyFromDoingThings'
    },
    initialize: function initialize() {
      this.stopListening(Hustle.Events, 'hustle:providers:reload', this.renderProvidersTables);
      this.listenTo(Hustle.Events, 'hustle:providers:reload', this.renderProvidersTables);
      this.render();
    },
    render: function render() {
      var $notConnectedWrapper = this.$el.find('#hustle-not-connected-providers-section'),
          $connectedWrapper = this.$el.find('#hustle-connected-providers-section');

      if (0 < $notConnectedWrapper.length && 0 < $connectedWrapper.length) {
        this.renderProvidersTables();
      }

      if (optinVars.integration_redirect) {
        this.handleIntegrationRedirect();
      }
    },
    renderProvidersTables: function renderProvidersTables() {
      var self = this,
          data = {};
      this.$el.find('.hustle-integrations-display').html("<div class=\"sui-notice hustle-integration-loading-notice\">\n\t\t\t\t\t\t<div class=\"sui-notice-content\">\n\t\t\t\t\t\t\t<div class=\"sui-notice-message\">\n\n\t\t\t\t\t\t\t\t<span class=\"sui-notice-icon sui-icon-loader sui-loading sui-md\" aria-hidden=\"true\"></span>\n\t\t\t\t\t\t\t\t<p>".concat(optinVars.fetching_list, "</p>\n\n\t\t\t\t\t\t\t</div>\n\t\t\t\t\t\t</div>\n\t\t\t\t\t</div>"));
      data.action = 'hustle_provider_get_providers';
      data._ajax_nonce = optinVars.providers_action_nonce; // eslint-disable-line camelcase

      data.data = {};
      var ajax = $.post({
        url: ajaxurl,
        type: 'post',
        data: data
      }).done(function (result) {
        if (result && result.success) {
          self.$el.find('#hustle-not-connected-providers-section').html(result.data.not_connected);
          self.$el.find('#hustle-connected-providers-section').html(result.data.connected);
        }
      }); // Remove the preloader.

      ajax.always(function () {
        self.$el.find('.hustle-integration-loading-notice').remove();
      });
    },
    // Prevent the enter key from opening integrations modals and breaking the page.
    preventEnterKeyFromDoingThings: function preventEnterKeyFromDoingThings(e) {
      if (13 === e.which) {
        // the enter key code
        e.preventDefault();
      }
    },
    connectIntegration: function connectIntegration(e) {
      Module.integrationsModal.open(e);
    },
    handleIntegrationRedirect: function handleIntegrationRedirect() {
      var data = optinVars.integration_redirect;
      var migrate = optinVars.integrations_migrate;
      window.history.pushState({}, document.title, optinVars.integrations_url);

      if ('notification' === data.action) {
        var status = 'success' === data.status ? 'success' : 'error',
            delay = data.delay ? data.delay : 10000;
        Module.Notification.open(status, data.message, delay);
      } // We're not doing CTCT yet.
      //if ( migrate.hasOwnProperty( 'provider_modal' ) && 'constantcontact' === migrate.provider_modal ) {
      //	Module.ProviderMigration.open( migrate.provider_modal );
      //}


      if (migrate.hasOwnProperty('provider_modal') && 'aweber' === migrate.provider_modal) {
        Module.ProviderMigration.open(migrate.provider_modal, migrate.integration_id);
      }

      if (migrate.hasOwnProperty('migration_notificaiton')) {
        var _status = 'success' === migrate.migration_notificaiton.status ? 'success' : 'error',
            _delay = migrate.migration_notificaiton.delay ? migrate.migration_notificaiton.delay : 10000;

        Module.Notification.open(_status, migrate.migration_notificaiton.message, _delay);
      }
    }
  });
  new integrationsView();
});
/* global moment */
Hustle.define('Entries.View', function ($) {
  'use strict';

  var page = '_page_hustle_entries';

  if (page !== pagenow.substr(pagenow.length - page.length)) {
    return;
  }

  var entriesView = Backbone.View.extend({
    el: '.sui-wrap-hustle',
    events: {
      'click .sui-pagination-wrap .hustle-open-inline-filter': 'openFilterInline',
      'click .sui-pagination-wrap .hustle-open-dialog-filter': 'openFilterModal',
      'click .hustle-delete-entry-button': 'openDeleteModal',
      'click .sui-active-filter-remove': 'removeFilter',
      'change input[name=search_email]': 'toggleClearButton',
      'change input[name=date_range]': 'toggleClearButton',
      'apply.daterangepicker input[name=date_range]': 'toggleClearButton',
      'click .hustle-entries-clear-filter': 'clearFilter'
    },
    initialize: function initialize() {
      this.initializeDaterangepicker();
      var entriesAlert = $('.hui-entries-alert');

      if (entriesAlert.length) {
        // Assign correct colspan.
        entriesAlert.attr('colspan', entriesAlert.closest('.sui-table').find('> thead tr th').length); // Show message.

        entriesAlert.find('i').hide();
        entriesAlert.find('span').removeClass('sui-screen-reader-text');
      }

      $('input[name=search_email]').trigger('change');
    },
    initializeDaterangepicker: function initializeDaterangepicker() {
      var $desktopInputs = this.$('.hui-box-actions input.hustle-entries-filter-date'),
          $mobileInput = this.$('#hustle-dialog--filter-entries input.hustle-entries-filter-date'),
          onApplyCallback = function onApplyCallback(ev, picker) {
        $(this).val(picker.startDate.format('MM/DD/YYYY') + ' - ' + picker.endDate.format('MM/DD/YYYY'));
      }; // Initialize for desktop fields.


      var options = {
        autoUpdateInput: false,
        autoApply: true,
        alwaysShowCalendars: true,
        locale: optinVars.daterangepicker,
        ranges: this.getDaterangepickerRanges()
      };
      $desktopInputs.daterangepicker(options);
      $desktopInputs.on('apply.daterangepicker', onApplyCallback); // Initialize for mobile field.

      var mobileOptions = Object.assign({
        parentEl: '#hustle-dialog--filter-entries .sui-box-body'
      }, options);
      $mobileInput.daterangepicker(mobileOptions);
      $mobileInput.on('apply.daterangepicker', onApplyCallback);
    },
    getDaterangepickerRanges: function getDaterangepickerRanges() {
      var rangesWithLabels = {};
      var labels = optinVars.daterangepicker.ranges,
          momentRanges = {
        today: [moment(), moment()],
        yesterday: [moment().subtract(1, 'days'), moment().subtract(1, 'days')],
        last_seven_days: [moment().subtract(6, 'days'), moment()],
        last_thirty_days: [moment().subtract(29, 'days'), moment()],
        this_month: [moment().startOf('month'), moment().endOf('month')],
        last_month: [moment().subtract(1, 'month').startOf('month'), moment().subtract(1, 'month').endOf('month')]
      };

      for (var key in momentRanges) {
        var label = labels[key],
            range = momentRanges[key];
        rangesWithLabels[label] = range;
      }

      return rangesWithLabels;
    },
    openFilterInline: function openFilterInline(e) {
      var $this = this.$(e.target),
          $wrapper = $this.closest('.sui-pagination-wrap'),
          $button = $wrapper.find('.sui-button-icon'),
          $filters = $this.closest('.hui-actions-bar').next('.sui-pagination-filter');
      $button.toggleClass('sui-active');
      $filters.toggleClass('sui-open');
      e.preventDefault();
      e.stopPropagation();
    },
    openFilterModal: function openFilterModal(e) {
      e.preventDefault();
      SUI.openModal('hustle-dialog--filter-entries', $(e.currentTarget)[0], this.$('#hustle-dialog--filter-entries .hustle-modal-close')[0], true);
    },
    removeFilter: function removeFilter(e) {
      var $this = this.$(e.target),
          possibleFilters = ['order_by', 'search_email', 'date_range'],
          currentFilter = $this.data('filter'),
          re = new RegExp('&' + currentFilter + '=[^&]*', 'i');

      if (-1 !== possibleFilters.indexOf(currentFilter)) {
        location.href = location.href.replace(re, '');
      }
    },
    openDeleteModal: function openDeleteModal(e) {
      e.preventDefault();
      var $this = $(e.target),
          data = {
        id: $this.data('id'),
        nonce: $this.data('nonce'),
        action: 'delete',
        title: $this.data('title'),
        description: $this.data('description'),
        actionClass: ''
      };
      Module.deleteModal.open(data, $this[0]);
    },
    toggleClearButton: function toggleClearButton(e) {
      var $form = $(e.target).closest('form'),
          $clearFilter = $form.find('.hustle-entries-clear-filter');

      if ($form.find('input[name=search_email]').val() || $form.find('input[name=date_range]').val()) {
        $clearFilter.prop('disabled', false);
      } else {
        $clearFilter.prop('disabled', true);
      }
    },
    clearFilter: function clearFilter(e) {
      e.preventDefault();
      this.$('input[name=search_email]').val('');
      this.$('input[name=date_range]').val('');
      this.toggleClearButton(e);
    }
  });
  new entriesView();
});
Hustle.define('ProviderNotice.View', function ($) {
  'use strict';

  var providerNotice = Backbone.View.extend({
    el: '.hustle-provider-notice',
    cookieKey: '',
    events: {
      'click .dismiss-provider-migration-notice': 'HideProviderNotice'
    },
    initialize: function initialize() {
      this.cookieKey = 'provider_migration_notice_';

      if ($('.hustle-provider-notice').length) {
        this.showProviderNotice();
      }
    },
    HideProviderNotice: function HideProviderNotice(e) {
      Optin.cookie.set(this.cookieKey + $(e.currentTarget).data('name'), 1, 7);
      location.reload();
    },
    showProviderNotice: function showProviderNotice() {
      var provider = $('.hustle-provider-notice').data('name'),
          notice = Optin.cookie.get(this.cookieKey + provider);

      if (1 !== notice) {
        $('.hustle_migration_notice__' + provider).show();
      }
    }
  });
  new providerNotice();
});
/* global tinyMCE */
Hustle.define('Settings.View', function ($, doc, win) {
  'use strict';

  var page = '_page_hustle_settings';

  if (page !== pagenow.substr(pagenow.length - page.length)) {
    return;
  }

  var viewSettings = Backbone.View.extend({
    el: '.sui-wrap-hustle',
    events: {
      'click .sui-sidenav .sui-vertical-tab a': 'sidenav',
      'change select.sui-mobile-nav': 'sidenavMobile',
      'click .sui-pagination-wrap > button': 'pagination',
      'click .hustle-load-on-click': 'addLoadingState',
      // Save settings.
      'click .hustle-settings-save': 'handleSave'
    },
    initialize: function initialize() {
      var me = this,
          recaptchaView = Hustle.get('Settings.reCaptcha_Settings'),
          topMetricsView = Hustle.get('Settings.Top_Metrics_View'),
          privacySettings = Hustle.get('Settings.Privacy_Settings'),
          permissionsView = Hustle.get('Settings.Permissions_View'),
          dataSettings = Hustle.get('Settings.Data_Settings'),
          palettesView = Hustle.get('Settings.Palettes');
      this.recaptchaView = new recaptchaView();
      new topMetricsView();
      new privacySettings();
      new permissionsView();
      new dataSettings();
      new palettesView();
      $(win).off('popstate', $.proxy(me.tabUpdate, me));
      $(win).on('popstate', $.proxy(me.tabUpdate, me));
      Hustle.Events.trigger('view.rendered', this);
      this.doActionsBasedOnUrl();
    },
    doActionsBasedOnUrl: function doActionsBasedOnUrl() {
      // Do stuff based on URL parameters.
      if (Module.Utils.getUrlParam('show-notice')) {
        // Display notices.
        var status = 'success' === Module.Utils.getUrlParam('show-notice') ? 'success' : 'error',
            notice = Module.Utils.getUrlParam('notice'),
            message = notice && 'undefined' !== optinVars.messages[notice] ? optinVars.messages[notice] : Module.Utils.getUrlParam('notice-message');

        if ('undefined' !== typeof message && message.length) {
          Module.Notification.open(status, message);
        }
      } else if (Module.Utils.getUrlParam('404-downgrade-modal')) {
        // Display the downgrade to 4.0.4 modal.
        if (this.$('#hustle-dialog--404-downgrade').length) {
          SUI.openModal('hustle-dialog--404-downgrade', 'hustle-popup-number');
        }
      }
    },
    sidenav: function sidenav(e) {
      var tabName = $(e.target).data('tab');

      if (tabName) {
        this.tabJump(tabName, true);
      }

      e.preventDefault();
    },
    sidenavMobile: function sidenavMobile(e) {
      var tabName = $(e.currentTarget).val();

      if (tabName) {
        this.tabJump(tabName, true);
      }
    },
    tabUpdate: function tabUpdate(e) {
      var state = e.originalEvent.state;

      if (state) {
        this.tabJump(state.tabSelected);
      }
    },
    tabJump: function tabJump(tabName, updateHistory) {
      var $tab = this.$el.find('a[data-tab="' + tabName + '"]'),
          $sidenav = $tab.closest('.sui-vertical-tabs'),
          $tabs = $sidenav.find('.sui-vertical-tab'),
          $content = this.$el.find('.sui-box[data-tab]'),
          $current = this.$el.find('.sui-box[data-tab="' + tabName + '"]');

      if (updateHistory) {
        history.pushState({
          tabSelected: tabName
        }, 'Hustle Settings', 'admin.php?page=hustle_settings&section=' + tabName);
      }

      $tabs.removeClass('current');
      $content.hide();
      $tab.parent().addClass('current');
      $current.show();
    },
    pagination: function pagination(e) {
      var $this = this.$(e.target),
          $wrapper = $this.closest('.sui-pagination-wrap'),
          $button = $wrapper.find('.sui-button-icon'),
          $filters = $wrapper.next('.sui-pagination-filter');
      $button.toggleClass('sui-active');
      $filters.toggleClass('sui-open');
      e.preventDefault();
      e.stopPropagation();
    },
    // ============================================================
    // Handle saving actions
    handleSave: function handleSave(e) {
      e.preventDefault();
      var self = this,
          $this = $(e.currentTarget),
          relatedFormId = $this.data('form-id'),
          actionData = $this.data();
      var data = new FormData();
      tinyMCE.triggerSave(); // Grab the form's data if the action has a related form.

      if ('undefined' !== typeof relatedFormId) {
        var $form = $('#' + relatedFormId);

        if ($form.length) {
          data = new FormData($form[0]); // Add unchecked checkboxes.

          $.each($form.find('input[type=checkbox]'), function () {
            var $input = $(this);

            if (!$input.is(':checked')) {
              data.append($input.attr('name'), '0');
            }
          });
        }
      }

      $.each(actionData, function (name, value) {
        return data.append(name, value);
      });
      data.append('_ajax_nonce', optinVars.current.save_settings_nonce);
      data.append('action', 'hustle_save_settings'); // Handle the button behavior.

      $this.addClass('sui-button-onload');
      $this.prop('disabled', true);
      $.ajax({
        url: ajaxurl,
        type: 'POST',
        data: data,
        contentType: false,
        processData: false
      }).done(function (res) {
        // If the response returned actionable data.
        if (res.data) {
          // If there's a defined callback, call it.
          if (res.data.callback && 'undefined' !== self[res.data.callback]) {
            // This calls the "action{ hustle action }" functions from this view.
            // For example: actionToggleStatus();
            self[res.data.callback]($this, res.data, res.success);
          }

          if (res.data.url) {
            if (true === res.data.url) {
              location.reload();
            } else {
              location.replace(res.data.url);
            }
          } else if (res.data.notification) {
            Module.Notification.open(res.data.notification.status, res.data.notification.message, res.data.notification.delay);
          } // Don't remove the 'loading' icon when redirecting/reloading.


          if (!res.data.url) {
            $('.sui-button-onload').removeClass('sui-button-onload');
            $this.prop('disabled', false);
          }
        } else {
          // Use default actions otherwise.
          if (res.success) {
            Module.Notification.open('success', optinVars.messages.settings_saved);
          } else {
            Module.Notification.open('error', optinVars.messages.something_went_wrong_reload);
          }

          $('.sui-button-onload').removeClass('sui-button-onload');
          $this.prop('disabled', false);
        }
      }).fail(function () {
        $('.sui-button-onload').removeClass('sui-button-onload');
        $this.prop('disabled', false);
        Module.Notification.open('error', optinVars.messages.something_went_wrong);
      });
    },

    /**
     * Callback action for when saving reCaptchas.
     *
     * @since 4.1.0
     */
    actionSaveRecaptcha: function actionSaveRecaptcha() {
      this.recaptchaView.maybeRenderRecaptchas();
    },
    addLoadingState: function addLoadingState(e) {
      var $button = $(e.currentTarget);
      $button.addClass('sui-button-onload');
    }
  });
  new viewSettings();
});