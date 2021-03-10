/* global hustleVars */
(function ($) {
  'use strict';

  var hustlePreview = {
    moduleId: null,
    moduleData: null,
    $module: null,
    open: function open(id, type) {
      var _this = this;

      var previewData = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : false;

      // Abort if we don't have an ID.
      if ('undefined' === typeof id) {
        return;
      }

      var isInline = 'embedded' === type || 'social_sharing' === type,
          $previewContainer = isInline ? $('#module-preview-inline-container') : $('#module-preview-container');
      $.ajax({
        url: hustleVars.ajaxurl,
        type: 'POST',
        data: {
          action: 'hustle_preview_module',
          id: id,
          previewData: previewData
        }
      }).then(function (res) {
        if (res.success) {
          $previewContainer.html(res.data.html);
          _this.$module = $previewContainer.find('.hustle-ui'); // Load select2 if this module has select fields.

          if (_this.$module.find('.hustle-select2').length) {
            HUI.select2();
          } // If there's a timepicker.


          if (_this.$module.find('.hustle-time').length) {
            HUI.timepicker('.hustle-time');
          } // If there's a datepicker.


          if (_this.$module.find('.hustle-date').length) {
            var _hustleVars = hustleVars,
                strings = _hustleVars.days_and_months;
            HUI.datepicker('.hustle-date', strings.days_full, strings.days_short, strings.days_min, strings.months_full, strings.months_short);
          }

          HUI.nonSharingSimulation(_this.$module);
          HUI.inputFilled();

          if (res.data.style) {
            $previewContainer.append(res.data.style);
          }

          if (res.data.script) {
            $previewContainer.append(res.data.script);
          }

          setTimeout(function () {
            return HUI.maybeRenderRecaptcha(_this.$module);
          }, 1000);
        }

        return {
          id: id,
          data: res.data.module
        };
      }, function () {// TODO: handle errors
      }).then(function (_ref) {
        var moduleId = _ref.id,
            data = _ref.data;
        _this.moduleId = moduleId;
        _this.moduleData = data; // Display the module.

        _this.showModule();
      });
    },
    showModule: function showModule() {
      var autohideDelay = '0' === String(this.$module.data('close-delay')) ? false : this.$module.data('close-delay');

      if ('popup' === this.moduleData.module_type) {
        HUI.popupLoad(this.$module[0], autohideDelay);
      } else if ('slidein' === this.moduleData.module_type) {
        HUI.slideinLayouts(this.$module[0]);
        HUI.slideinLoad(this.$module[0], autohideDelay);
        $(window).on('resize', function () {
          if (this.$module) {
            HUI.slideinLayouts(this.$module[0]);
          }
        });
      } else {
        HUI.inlineResize(this.$module[0]);
        HUI.inlineLoad(this.$module[0]);
      }
    },
    reloadModule: function reloadModule() {
      var _this2 = this;

      if (this.$module.is(':visible')) {
        var delay = 0;

        if ('popup' === this.moduleData.module_type) {
          HUI.popupClose(this.$module[0], 0);
          delay = 2000;
        } else if ('slidein' === this.moduleData.module_type) {
          HUI.slideinClose(this.$module[0], 0);
          delay = 500;
        } // TODO: replace this timeout by an event for
        // when after the module is hidden when introduced into HUI.


        setTimeout(function () {
          return _this2.showModule();
        }, delay);
      } else {
        this.showModule();
      }
    },
    previewClosed: function previewClosed() {
      this.$module = null;
      $('#module-preview-container').empty();
      $('#module-preview-inline-container').empty();
    }
  };
  window.addEventListener('message', hustleReceiveMessage, false);

  function hustleReceiveMessage(event) {
    if (event.origin !== window.location.origin || event.source !== window.parent) {
      return;
    }

    var action = event.data.action;

    if ('open' === action) {
      hustlePreview.open(event.data.moduleId, event.data.moduleType, event.data.previewData);
    } else if ('close' === action) {
      hustlePreview.previewClosed();
    } else if ('reload' === action) {
      hustlePreview.reloadModule();
    }
  } // Prevent links from doing anything on the preview page.


  $('a:not(.hustle-button)').on('click', function (e) {
    e.preventDefault();
  });
})(jQuery);